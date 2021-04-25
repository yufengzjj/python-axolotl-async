# -*- coding: utf-8 -*-

import abc


class SignedPreKeyStore(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    async def loadSignedPreKey(self, signedPreKeyId):
        pass

    @abc.abstractmethod
    async def loadSignedPreKeys(self):
        pass

    @abc.abstractmethod
    async def storeSignedPreKey(self, signedPreKeyId, signedPreKeyRecord):
        pass

    @abc.abstractmethod
    async def containsSignedPreKey(self, signedPreKeyId):
        pass

    @abc.abstractmethod
    async def removeSignedPreKey(self, signedPreKeyId):
        pass
