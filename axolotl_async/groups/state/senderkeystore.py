# -*- coding: utf-8 -*-

import abc


class SenderKeyStore(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    async def storeSenderKey(self, senderKeyId, senderKeyRecord):
        """
        :type senderKeyId: str
        :type senderKeyRecord: SenderKeyRecord
        """

    @abc.abstractmethod
    async def loadSenderKey(self, senderKeyId):
        """
        :type senderKeyId: str
        """
