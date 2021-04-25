# -*- coding: utf-8 -*-

import abc


class PreKeyStore(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    async def loadPreKey(self, preKeyId):
        pass

    @abc.abstractmethod
    async def storePreKey(self, preKeyId, preKeyRecord):
        pass

    @abc.abstractmethod
    async def containsPreKey(self, preKeyId):
        pass

    @abc.abstractmethod
    async def removePreKey(self, preKeyId):
        pass
