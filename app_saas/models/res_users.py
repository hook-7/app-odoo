# -*- coding: utf-8 -*-

try:
    import urlparse
except:
    from urllib.parse import urlparse
try:
    import urllib2
except:
    from urllib import request as urllib2



from odoo import api, fields, models, _
from odoo.exceptions import AccessDenied, UserError
from odoo.addons.auth_signup.models.res_users import SignupError
from odoo.http import request, Response
from odoo.tools.misc import ustr

from ast import literal_eval
import json
import requests
from datetime import timedelta
import random

import logging
_logger = logging.getLogger(__name__)

class OauthBindError(Exception):
    # 增加一种错误类型
    pass

class ResUsers(models.Model):
    _inherit = 'res.users'
    
    @api.model
    def auth_oauth(self, provider, params):
        # 这里原生是没处理code模式，此处将增加使用code取token，不在 controller 中处理
        code = params.get('code', False)
        access_token = params.get('access_token')
        oauth_provider = self.env['auth.oauth.provider'].sudo().browse(provider)
        
        kw = {}
        if oauth_provider.code_endpoint and code and not access_token:
            # odoo 特殊处理，用code取token
            params.update({
                'scope': oauth_provider.scope or '',
                'client_id': oauth_provider.client_id or '',
            })
            if hasattr(oauth_provider, 'client_secret') and oauth_provider.client_secret:
                params.update({
                    'client_secret': oauth_provider.client_secret or '',
                })
            response = requests.get(oauth_provider.code_endpoint, params=params, timeout=30)
            if response.ok:
                ret = response.json()
                # todo: 客户机首次连接时，取到的 server 端 key 写入 provider 的 client_secret
                if ret.get('push_client_secret') and hasattr(oauth_provider, 'client_secret'):
                    oauth_provider.write({'client_secret': ret.get('push_client_secret')})
                    self._cr.commit()
            kw = {**ret, **params}
            kw.pop('code', False)
        self = self.with_context(auth_extra=kw)
        res = super(ResUsers, self).auth_oauth(provider, kw)
        return res

    def _auth_oauth_signin(self, provider, validation, params):
        # 用户绑定的额外处理，如果有同 login 用户则直接绑定
        # todo: 当前不管多公司，在 social_login 里有更细节判断，后续优化
        # todo: 当前同名就写 oauth 信息，不安全，要优化
        oauth_provider = self.env['auth.oauth.provider'].sudo().browse(provider)
        if oauth_provider and oauth_provider.scope.find('odoo') >= 0:
            oauth_uid =validation.get('user_id')
            if oauth_uid:
                odoo_user = self.sudo().search([('login', '=', oauth_uid)], limit=1)
                if odoo_user and not (odoo_user.oauth_access_token and odoo_user.oauth_provider_id and odoo_user.oauth_uid):
                    vals = {
                        'oauth_provider_id': provider,
                        'oauth_access_token': params.get('access_token'),
                        'oauth_uid': oauth_uid,
                    }
                    odoo_user.write(vals)
                    _logger.info('========= _auth_oauth_signin res.users write：%s' % vals)
                    self._cr.commit()
                    return odoo_user.user_id.login
        res = super(ResUsers, self)._auth_oauth_signin(provider, validation, params)
        return res
    
    def _create_user_from_template(self, values):
        # 处理odooapp.cn 为 server 时 默认为内部用户
        oauth_provider_id = values.get('oauth_provider_id')
        if oauth_provider_id:
            provider = request.env['auth.oauth.provider'].sudo().browse(int(oauth_provider_id))
            if provider:
                template_user = provider.user_template_id
                if not template_user and provider.scope.find('odoo') >= 0:
                    template_user = self.sudo().env.ref('base.default_user', False)
                if not template_user:
                    template_user_id = literal_eval(self.env['ir.config_parameter'].sudo().get_param('base.template_portal_user_id', 'False'))
                    template_user = self.sudo().browse(template_user_id)

                if not values.get('login'):
                    raise ValueError(_('Signup: no login given for new user'))
                if not values.get('partner_id') and not values.get('name'):
                    raise ValueError(_('Signup: no name or partner given for new user'))

                # create a copy of the template user (attached to a specific partner_id if given)
                values['active'] = True
                try:
                    with self.env.cr.savepoint():
                        return template_user.sudo().with_context(no_reset_password=True).copy(values)
                except Exception as e:
                    # copy may failed if asked login is not available.
                    raise SignupError(ustr(e))
        res = super(ResUsers, self)._create_user_from_template(values)
        self._cr.commit()
        return res

    @api.model
    def _generate_signup_values(self, provider, validation, params):
        # 此处生成 创建 odoo user 的初始值，增加字段如头像
        res = super()._generate_signup_values(provider, validation, params)
        # 后置增加字段，包括 headimgurl
        if validation.get('mobile'):
            res['mobile'] = validation.get('mobile')
        if validation.get('headimgurl'):
            res['image_1920'] = self.sudo()._get_image_from_url(validation.get('headimgurl'))
        return res

    def _rpc_api_keys_only(self):
        # 可直接使用 oauth_access_token 作为 password 登录
        self.ensure_one()
        return self.oauth_access_token or super()._rpc_api_keys_only()
