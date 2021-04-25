# -*- coding: utf-8 -*-

import abc


class IdentityKeyStore(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    async def getIdentityKeyPair(self):
        pass

    @abc.abstractmethod
    async def getLocalRegistrationId(self):
        pass

    @abc.abstractmethod
    async def saveIdentity(self, recepientId, identityKey):
        pass

    @abc.abstractmethod
    async def isTrustedIdentity(self, recepientId, identityKey):
        pass
