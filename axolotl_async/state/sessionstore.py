# -*- cosing: utf-8 -*-

import abc


class SessionStore(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    async def loadSession(self, recepientId, deviceId):
        pass

    @abc.abstractmethod
    async def getSubDeviceSessions(self, recepientId):
        pass

    @abc.abstractmethod
    async def storeSession(self, recepientId, deviceId, sessionRecord):
        pass

    @abc.abstractmethod
    async def containsSession(self, recepientId, deviceId):
        pass

    @abc.abstractmethod
    async def deleteSession(self, recepientId, deviceId):
        pass

    @abc.abstractmethod
    async def deleteAllSessions(self, recepientId):
        pass
