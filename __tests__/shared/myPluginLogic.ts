// noinspection ES6PreferShortImport

import { TAgent, IMessageHandler, ICredentialPlugin, IDIDManager, IKeyManager, IDataStore, IDataStoreORM, IResolver } from '@veramo/core-types'
import { createBrainSharePostMessage } from '../../src/message-handler/brainshare-message-handler.js'
import { IDIDComm } from '@veramo/did-comm'
import { ICredentialIssuerLD } from '@veramo/credential-ld'
import { MessagingRouter, RequestWithAgentRouter } from '@veramo/remote-server'
import express from 'express'
import { Server } from 'http'

type ConfiguredAgent = TAgent<
  IDIDManager & 
  IKeyManager & 
  IDIDComm & 
  ICredentialPlugin &
  IMessageHandler &
  IDataStore &
  IDataStoreORM
>

export default (testContext: {
  getAgent: () => ConfiguredAgent
  setup: () => Promise<boolean>
  tearDown: () => Promise<boolean>
}) => {
  describe('my plugin', () => {
    let agent: ConfiguredAgent
    let didCommEndpointServer: Server
    let listeningPort = Math.round(Math.random() * 32000 + 2048)

    beforeAll(async () => {
      await testContext.setup()
      agent = testContext.getAgent()

      const requestWithAgent = RequestWithAgentRouter({ agent })
      await new Promise((resolve) => {
        //setup a server to receive HTTP messages and forward them to this agent to be processed as DIDComm messages
        const app = express()
        // app.use(requestWithAgent)
        app.use(
          '/messaging',
          requestWithAgent,
          MessagingRouter({
            metaData: { type: 'DIDComm', value: 'integration test' },
          }),
        )
        didCommEndpointServer = app.listen(listeningPort, () => {
          resolve(true)
        })
      })
    })
    afterAll(async () => {
      await testContext.tearDown()
      didCommEndpointServer.close()
    })

    it('should correctly send between 2 DIDs with service endpoitns', async () => {
      const sender = await agent.didManagerCreate({
        "alias": "sender",
        "provider": "did:peer",
        "kms": "local",
        "options": {
          "num_algo":2 , 
          "service" : {
            "id":"12344",
            "type":"DIDCommMessaging",
            "serviceEndpoint":`http://localhost:${listeningPort}/messaging`,
            "description":"an endpoint"
          }
        }
      })
      const receiver = await agent.didManagerCreate({
        "alias": "receiver",
        "provider": "did:peer",
        "kms": "local",
        "options": {
          "num_algo":2 , 
          "service" : {
            "id":"12345",
            "type":"DIDCommMessaging",
            "serviceEndpoint":`http://localhost:${listeningPort}/messaging`,
            "description":"an endpoint"
          }
        }
      })

      const post = await agent.createVerifiableCredential({
        credential: {
          issuer: { id: sender.did },
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential', 'BrainSharePost'],
          issuanceDate: new Date().toISOString(),
          credentialSubject: {
            post: 'Whatever dude!',
          },
        },
        proofFormat: 'jwt'
      })
      const postMessage = createBrainSharePostMessage(post, sender.did, receiver.did)

      const getNumCredentials1 = await agent.dataStoreORMGetVerifiableCredentialsCount()

      const packed = await agent.packDIDCommMessage({
        packing: 'authcrypt',
        message: postMessage
      })

      // const res = await agent.handleMessage({ raw: packed.message })
      // console.log("res: ", res)

      const res = await agent.sendDIDCommMessage({ 
        messageId: 'somefakeid1', 
        packedMessage: packed, 
        recipientDidUrl: receiver.did
      })
      console.log("res: ", res)
      
      const getNumCredentials2 = await agent.dataStoreORMGetVerifiableCredentialsCount()

      expect(getNumCredentials2).toEqual(getNumCredentials1 + 1)
      
      expect(res).toBeDefined()
    })
  })
}
