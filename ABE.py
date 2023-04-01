"""
| Article: "Online/Offline MA-CP-ABE with Cryptographic Reverse Firewalls for IoT"
| Notes: Implemented the scheme in Section 4
|
|
| type:      attribute-based encryption & cryptographic reverse firewall & Online/offline & multi-authority & ciphertext-policy
| setting:   Pairing

:Date:       2023
"""


from charm.toolbox.pairinggroup import PairingGroup, pair, G1, GT
from charm.toolbox.secretutil import SecretUtil


# ABE type
class ABE(object):

    def __init__(self, security_parameter, verbose=False):
        self.group = PairingGroup(security_parameter)
        self.util = SecretUtil(self.group, verbose)
        self.policy = None
        self.attributes_in_policy = self.util.getAttributeList(self.policy)

    def global_setup(self):
        """ 1. global_setup(lambda, U) ---> GP

        :return: the global system parameter (GP)
        """
        g = self.group.random(G1)
        h, u, v, w = self.group.random(G1), self.group.random(G1), self.group.random(G1), self.group.random(G1)

        GP = {'g': g, 'h': h, 'u': u, 'v': v, 'w': w}

        return GP

    def wga_global_setup(self, GP):
        """ 2. wga_global_setup(GP) ---> GP'

        :param GP: the global system parameter
        :return: the updated GP (GP')
        """
        a, b, c = self.group.random(), self.group.random(), self.group.random()
        d, e = self.group.random(), self.group.random()
        g_, u_, h_, w_, v_ = GP['g'] ** a, GP['u'] ** b, GP['h'] ** c, GP['w'] ** d, GP['v'] ** e
        eg_g_ = pair(g_, g_)

        GP_ = {'g_': g_, 'u_': u_, 'h_': h_, 'w_': w_, 'v_': v_, 'eg_g_': eg_g_}

        return GP_

    def ga_setup(self, GP_):
        """ 3. ga_setup(GP') ---> (GPK, GMK)

        :param GP_: the updated GP
        :return: the global public key and the global master key (GPK, GMK)
        """
        alpha = self.group.random()
        GPK = GP_['eg_g_'] ** alpha
        GMK = alpha

        return GPK, GMK

    def wga_ga_setup(self, GP_, GPK, GMK):
        """ 4. wga_ga_setup(GP', GPK, GMK) ---> (GPK', GMK', f)

        :param GP_: the updated GP
        :param GPK: the global public key
        :param GMK: the global master key
        :return: the updated GPK and the updated GMK (GPK', GMK'), keeping random value (f) by itself
        """
        f = self.group.random()
        GPK_ = GPK * GP_['eg_g_'] ** f
        GMK_ = GMK + f

        return GPK_, GMK_, f

    def aa_setup(self, GP_, authority_list):
        """ 5. aa_setup(GP', k, Uk) ---> (APKk, AMKk)

        :param GP_: the updated GP
        :param authority_list: A collection of attribute authorities with numbered and administrative attributes
        :return: the authority public key and the authority secret key (APKk, AMKk)
        """
        for theta in range(len(authority_list)):
            alpha = self.group.random()
            __u, __h = GP_['u_'] ** alpha, GP_['h_'] ** alpha
            authority_list[theta].APK = (__u, __h)
            authority_list[theta].AMK = alpha

    def waa_setup(self, GP_, authority_list):
        """ 6. waa_setup(GP', APKk, AMKk) ---> (APKk', AMKK')

        :param GP_: the updated GP
        :param authority_list: A collection of attribute authorities with numbered and administrative attributes
        :return: the updated APKk and the updated AMKk (APKk', AMKk')
        """
        for theta in range(len(authority_list)):
            _alpha = self.group.random()
            __u_, __h_ = authority_list[theta].APK[0] * GP_['u_'] ** _alpha, authority_list[theta].APK[1] * GP_['h_'] ** _alpha
            authority_list[theta].APK_ = (__u_, __h_)
            authority_list[theta].AMK_ = authority_list[theta].AMK + _alpha

    def encrypt_off(self, GP_, GPK_, authority_list):
        """ 7. encrypt_off(GP', GPK', APK') ---> CToff

        :param GP_: the updated GP
        :param GPK_: the updated GPK
        :param authority_list: A collection of attribute authorities with numbered and administrative attributes
        :return: the offline ciphertext (CToff)
        """
        s = self.group.random()
        Km = GPK_ ** s
        C0_ = GP_['g_'] ** s

        tj, Cj1_, Cj2_, Cj3_ = {}, {}, {}, {}
        for j in self.attributes_in_policy:
            t = self.group.random()
            tj[j] = t
            Cj2_[j] = GP_['g_'] ** t
            Cj3_[j] = GP_['v_'] ** t
            for theta in range(len(authority_list)):
                if j in authority_list[theta].authority_attributes:
                    Cj1_[j] = authority_list[theta].APK_[1] ** -t
                    break

        CToff = {'s': s, 'Km': Km, 'C0_': C0_, 'tj': tj, 'Cj1_': Cj1_, 'Cj2_': Cj2_, 'Cj3_': Cj3_}

        return CToff

    def encrypt_on(self, GP_, authority_list, m, CToff):
        """ 8. encrypt_on(GP', APKk, m, CToff) ---> CT

        :param GP_: the updated GP
        :param authority_list: A collection of attribute authorities with numbered and administrative attributes
        :param m: the plaintext
        :param CToff: the offline ciphertext
        :return: the online ciphertext with policy (CT)
        """
        s = CToff['s']
        C = m * CToff['Km']
        C0 = CToff['C0_']
        secret_shares = self.util.calculateSharesDict(s, self.policy)

        Cj1, Cj2, Cj3 = {}, {}, {}
        for j in self.attributes_in_policy:
            Cj2[j] = CToff['Cj2_'][j]
            Cj3[j] = CToff['Cj3_'][j] * GP_['w_'] ** secret_shares[j]
            for theta in range(len(authority_list)):
                if j in authority_list[theta].authority_attributes:
                    Cj1[j] = CToff['Cj1_'][j] * authority_list[theta].APK_[0] ** -CToff['tj'][j]
                    break

        CT = {'C': C, 'C0': C0, 'Cj1': Cj1, 'Cj2': Cj2, 'Cj3': Cj3}

        return CT

    def wdo_encrypt_off(self, GP_, GMK_, authority_list):
        """ 9. wdo_encrypt_off(GP', GMK', APKk') ---> IT

        :param GP_: the updated GP
        :param GMK_: the updated GMK
        :param authority_list: A collection of attribute authorities with numbered and administrative attributes
        :return: the offline intermediate ciphertext (IT)
        """
        _s = self.group.random()
        __Km = GP_['eg_g_'] ** (GMK_ * _s)
        __C0 = GP_['g_'] ** _s

        _tj, __Cj1, __Cj2, __Cj3 = {}, {}, {}, {}
        for j in self.attributes_in_policy:
            _t = self.group.random()
            _tj[j] = _t
            __Cj2[j] = GP_['g_'] ** _t
            __Cj3[j] = GP_['v_'] ** _t
            for theta in range(len(authority_list)):
                if j in authority_list[theta].authority_attributes:
                    __Cj1[j] = authority_list[theta].APK_[1] ** -_t
                    break

        IT = {'_s': _s, '__Km': __Km, '__C0': __C0, '_tj': _tj, '__Cj1': __Cj1, '__Cj2': __Cj2, '__Cj3': __Cj3}

        return IT

    def wdo_encrypt_on(self, GP_, IT, CT, authority_list):
        """ 10. wdo_encrypt_on(GP', IT, CT) ---> CT'

        :param GP_: the updated GP
        :param IT: the offline intermediate ciphertext
        :param CT: the online ciphertext with policy
        :param authority_list: A collection of attribute authorities with numbered and administrative attributes
        :return: the updated CT (CT')
        """
        _s = IT['_s']
        _secret_shares = self.util.calculateSharesDict(_s, self.policy)
        __C_ = CT['C'] * IT['__Km']
        __C0_ = CT['C0'] * IT['__C0']

        __Cj1_, __Cj2_, __Cj3_ = {}, {}, {}
        for j in self.attributes_in_policy:
            __Cj2_[j] = CT['Cj2'][j] * IT['__Cj2'][j]
            __Cj3_[j] = CT['Cj3'][j] * IT['__Cj3'][j] * GP_['w_'] ** _secret_shares[j]
            for theta in range(len(authority_list)):
                if j in authority_list[theta].authority_attributes:
                    __Cj1_[j] = CT['Cj1'][j] * IT['__Cj1'][j] * authority_list[theta].APK_[0] ** -IT['_tj'][j]
                    break

        CT_ = {'policy': self.policy, '__C_': __C_, '__C0_': __C0_, '__Cj1_': __Cj1_, '__Cj2_': __Cj2_, '__Cj3_': __Cj3_}

        return CT_

    def ga_keygen_off(self, GP_, GMK):
        """ 11. ga_keygen_off(GP', GMK) ---> ugsk

        :param GP_: the updated global parameter
        :param GMK: the global master key
        :return: a portion of the decryption key (ugsk)
        """
        r = self.group.random()
        K0 = GP_['g_'] ** GMK * GP_['w_'] ** r
        K3 = GP_['g_'] ** r
        D = GP_['v_'] ** -r

        ugsk = {'r': r, 'K0': K0, 'K3': K3, 'D': D}

        return ugsk

    def wga_gakeygen_off(self, GP_, f):
        """ 12. wga_gakeygen_off(GP', f) ---> ISK

        :param GP_: the updated GP
        :param f: the random value
        :return: the intermediate secret key (ISK)
        """
        _r = self.group.random()
        __K0 = GP_['g_'] ** f * GP_['w_'] ** _r
        __K3 = GP_['g_'] ** _r
        __D = GP_['v_'] ** -_r

        ISK = {'_r': _r, '__K0': __K0, '__K3': __K3, '__D': __D}

        return ISK

    def wga_gakeygen_on(self, GP_, ISK, ugsk):
        """ 13. wga_gakeygen_on(GP', ISK, ugsk) ---> ugsk'

        :param GP_: the updated GP
        :param ISK: the intermediate secret key
        :param ugsk: a portion of the decryption key
        :return: the updated ugsk (ugsk')
        """
        __K0_ = ISK['__K0'] * ugsk['K0']
        __K3_ = ISK['__K3'] * ugsk['K3']
        __D_ = GP_['v_'] ** -(ugsk['r'] + ISK['_r'])

        ugsk_ = {'__K0_': __K0_, '__K3_': __K3_, '__D_': __D_}

        return ugsk_

    def aa_keygen_off(self, GP_, authority_list, user_attributes):
        """ 14. aa_keygen_off(GP', AMKk) ---> uaskoff

        :param GP_: the updated GP
        :param authority_list: A collection of attribute authorities with numbered and administrative attributes
        :param user_attributes: the attributes of user Alex
        :return: the pre-decryption key (uaskoff)
        """
        ri, Ki1_, Ki2_ = {}, {}, {}
        for attr in user_attributes:
            r = self.group.random()
            ri[attr] = r
            Ki2_[attr] = GP_['h_'] ** r
            for theta in range(len(authority_list)):
                if attr in authority_list[theta].authority_attributes:
                    Ki1_[attr] = GP_['g_'] ** (r / authority_list[theta].AMK_)
                    break

        uaskoff = {'ri': ri, 'Ki1_': Ki1_, 'Ki2_': Ki2_}

        return uaskoff

    def aa_keygen_on(self, GP_, uaskoff, user_attributes):
        """ 15. aa_keygen_on(GP', uaskoff, SGID) ---> uaskon

        :param GP_: the updated GP
        :param uaskoff: the pre-decryption key
        :param user_attributes: the attributes of user Alex
        :return: user decryption key (uaskon)
        """
        Ki1, Ki2 = {}, {}
        for attr in user_attributes:
            Ki1[attr] = uaskoff['Ki1_'][attr]
            Ki2[attr] = uaskoff['Ki2_'][attr] * GP_['u_'] ** uaskoff['ri'][attr]

        uaskon = {'Ki1': Ki1, 'Ki2': Ki2}

        return uaskon

    def waa_keygen_off(self, GP_, authority_list, user_attributes):
        """ 16. waa_keygen_off(GP', AMKk') ---> uaskoff'

        :param GP_: the updated GP
        :param authority_list: A collection of attribute authorities with numbered and administrative attributes
        :param user_attributes: the attributes of user Alex
        :return: the updated uaskoff (uaskoff')
        """
        _ri, __Ki1, __Ki2 = {}, {}, {}
        for attr in user_attributes:
            _r = self.group.random()
            _ri[attr] = _r
            __Ki2[attr] = GP_['h_'] ** _r
            for theta in range(len(authority_list)):
                if attr in authority_list[theta].authority_attributes:
                    __Ki1[attr] = GP_['g_'] ** (_r / authority_list[theta].AMK_)
                    break

        uaskoff_ = {'_ri': _ri, '__Ki1': __Ki1, '__Ki2': __Ki2}

        return uaskoff_

    def waa_keygen_on(self, GP_, uaskon, uaskoff_, user_attributes):
        """ 17. waa_keygen_on(GP', uaskon, uaskoff', SGID) ---> uaskon'

        :param GP_: the updated GP
        :param uaskon: user decryption key
        :param uaskoff_: the updated uaskoff
        :param user_attributes: the attributes of user Alex
        :return: the updated uaskon (uaskon')
        """
        __Ki1_, __Ki2_ = {}, {}
        for attr in user_attributes:
            __Ki1_[attr] = uaskon['Ki1'][attr] * uaskoff_['__Ki1'][attr]
            __Ki2_[attr] = uaskon['Ki2'][attr] * uaskoff_['__Ki2'][attr] * GP_['u_'] ** uaskoff_['_ri'][attr]

        uaskon_ = {'__Ki1_': __Ki1_, '__Ki2_': __Ki2_}

        return uaskon_

    def keygen_ran(self, ugsk_, uaskon_, user_attributes):
        """ 18. keygen_ran(ugsk', uaskon') ---> (TK, RK)

        :param ugsk_: the updated ugsk
        :param uaskon_: the updated uaskon
        :param user_attributes: the attributes of user Alex
        :return: the conversion key (TK) and the recovery key (RK)
        """
        tal = self.group.random()
        _K0 = ugsk_['__K0_'] ** (1 / tal)
        _K3 = ugsk_['__K3_'] ** (1 / tal)
        _D = ugsk_['__D_'] ** (1 / tal)

        _Ki1, _Ki2 = {}, {}
        for attr in user_attributes:
            _Ki1[attr] = uaskon_['__Ki1_'][attr] ** (1 / tal)
            _Ki2[attr] = uaskon_['__Ki2_'][attr] ** (1 / tal)

        TK = {'SGID': user_attributes, '_K0': _K0, '_K3': _K3, '_D': _D, '_Ki1': _Ki1, '_Ki2': _Ki2}
        RK = tal

        return TK, RK

    def wdu_tkupdate(self, TK):
        """ 19. wdu_tkupdate(TK) ---> TK', Rk'

        :param TK: the conversion key
        :return: the updated TK (TK') and keeping (RK') by itself
        """
        beta = self.group.random()
        _K0_ = TK['_K0'] ** (1 / beta)
        _K3_ = TK['_K3'] ** (1 / beta)
        _D_ = TK['_D'] ** (1 / beta)

        _Ki1_, _Ki2_ = {}, {}
        for attr in TK['SGID']:
            _Ki1_[attr] = TK['_Ki1'][attr] ** (1 / beta)
            _Ki2_[attr] = TK['_Ki2'][attr] ** (1 / beta)

        TK_ = {'SGID': TK['SGID'], '_K0_': _K0_, '_K3_': _K3_, '_D_': _D_, '_Ki1_': _Ki1_, '_Ki2_': _Ki2_}
        RK_ = beta

        return TK_, RK_

    def decrypt_out(self, TK_, CT_):
        """ 20. decrypt_out(TK', CT') ---> TCT

        :param TK_: the updated TK
        :param CT_: the updated CT
        :return: the transformed ciphertext (TCT)
        """
        coefficients = self.util.getCoefficients(self.policy)
        pruned_list = self.util.prune(self.policy, TK_['SGID'])

        # attributes do not meet the access policy
        if pruned_list is False:
            return

        # attributes meet the access policy
        "分子"
        numerator = pair(TK_['_K0_'], CT_['__C0_'])
        "分母"
        denominator = self.group.init(GT, 1)

        for i in pruned_list:
            x = str(i)
            denominator *= (pair(TK_['_Ki1_'][x], CT_['__Cj1_'][x]) * pair(TK_['_Ki2_'][x] * TK_['_D_'], CT_['__Cj2_'][x]) *

                            pair(TK_['_K3_'], CT_['__Cj3_'][x])) ** coefficients[x]

        B = numerator / denominator

        TCT = {'__C_': CT_['__C_'], 'B': B}

        return TCT

    def wdu_decrypt(self, TCT, RK_):
        """ 21. wdu_decrypt(TCT, RK') ---> TCT'

        :param TCT: the transformed ciphertext
        :param RK_: the updated RK
        :return: the updated TCT (TCT')
        """
        TCT_ = {'B_beta': TCT['B'] ** RK_, '__C_': TCT['__C_']}

        return TCT_

    def decrypt_user(self, RK, TCT_):
        """ 22. decrypt_user(RK, TCT') ---> m

        :param RK: the retrieval key
        :param TCT_: the updated TCT
        :return: recover the plaintext (m)
        """
        m = TCT_['__C_'] / TCT_['B_beta'] ** RK

        return m
