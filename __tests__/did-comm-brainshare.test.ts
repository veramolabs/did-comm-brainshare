// noinspection ES6PreferShortImport

import { getConfig } from '@veramo/cli/build/setup'
import { createObjects } from '@veramo/cli/build/lib/objectCreator'
import { DataSource } from 'typeorm'
import fs from 'fs'
import { jest } from '@jest/globals'

import { createAgent } from '@veramo/core'
import { TAgent, IMessageHandler, ICredentialPlugin, IDIDManager, IKeyManager, IIdentifier, IDataStoreORM, IResolver } from '@veramo/core-types'
import { BrainShareMessageHandler, createBrainSharePostMessage, getTxtRecords } from '../src/message-handler/brainshare-message-handler.js'
import { IDIDComm, DIDComm, DIDCommHttpTransport, DIDCommMessageHandler } from '@veramo/did-comm'
import { CredentialIssuer } from '@veramo/credential-w3c'
import {   
  ContextDoc,
  CredentialIssuerLD,
  LdDefaultContexts,
  VeramoEcdsaSecp256k1RecoverySignature2020,
  VeramoEd25519Signature2020
} from '@veramo/credential-ld'
import { MessagingRouter, RequestWithAgentRouter } from '@veramo/remote-server'
import express from 'express'
import { Server } from 'http'
import * as dns from 'dns'
import { IEventListener } from '@veramo/core'
import { Entities, IDataStore, DataStore, DataStoreORM, MetaData, migrations } from '@veramo/data-store'
// import { FakeDidProvider, FakeDidResolver } from '@veramo/test-utils'
import { getResolver as getDidPeerResolver,PeerDIDProvider } from '@veramo/did-provider-peer'
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager'
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager'
import { KeyManagementSystem } from '@veramo/kms-local'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { MessageHandler } from '@veramo/message-handler'
import { Resolver } from 'did-resolver'

const DIDCommEventSniffer: IEventListener = {
  eventTypes: ['DIDCommV2Message-sent', 'DIDCommV2Message-received'],
  onEvent: jest.fn(() => Promise.resolve()),
}

  const customContext: Record<string, ContextDoc> = {
    'custom:example.context': {
      '@context': {
        post: 'custom:example.context#blank',
      },
    },
  }

describe('brainshare-message-handler', () => {
  let sender: IIdentifier
  let recipient: IIdentifier
  let agent: TAgent<IResolver & IKeyManager & IDIDManager & IDIDComm & IMessageHandler & IDataStore>
  let didCommEndpointServer: Server
  let listeningPort = Math.round(Math.random() * 32000 + 2048)
  let dbConnection: DataSource

  beforeAll(async () => {
    dbConnection = new DataSource({
      name: 'test',
      type: 'sqlite',
      database: ':memory:',
      synchronize: false,
      migrations: migrations,
      migrationsRun: true,
      logging: false,
      entities: Entities,
    })
    agent = createAgent<IResolver & IKeyManager & IDIDManager & IDIDComm & IMessageHandler & IDataStore>({
      plugins: [
        new KeyManager({
          store: new MemoryKeyStore(),
          kms: {
            // @ts-ignore
            local: new KeyManagementSystem(new MemoryPrivateKeyStore()),
          },
        }),
        new DIDManager({
          providers: {
            'did:peer': new PeerDIDProvider({
              defaultKms: 'local'
            }),
            // 'did:web': new WebDIDProvider({ defaultKms: 'local' })
          },
          store: new MemoryDIDStore(),
          defaultProvider: 'did:peer',
        }),
        new DIDResolverPlugin({
          resolver: new Resolver({
            ...getDidPeerResolver(),
          }),
        }),
        // @ts-ignore
        new DIDComm([new DIDCommHttpTransport()]),
        new MessageHandler({
          messageHandlers: [
            // @ts-ignore
            new DIDCommMessageHandler(),
            // @ts-ignore
            new BrainShareMessageHandler(),
          ],
        }),
        new DataStore(dbConnection),
        new DataStoreORM(dbConnection),
        DIDCommEventSniffer,
        new CredentialIssuer(),
        new CredentialIssuerLD({
          contextMaps: [LdDefaultContexts, customContext],
          suites: [new VeramoEd25519Signature2020(), new VeramoEcdsaSecp256k1RecoverySignature2020()],
        }),
      ],
    })

    sender = await agent.didManagerCreate({
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

    // console.log("sender: ", sender)
    recipient = await agent.didManagerCreate({
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

    // console.log('sender: ', sender)
    // console.log('recipient: ', recipient)

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
    try {
      await new Promise((resolve, reject) => didCommEndpointServer?.close(resolve))
    } catch (e: any) {
      // nop
    }
    try {
      dbConnection?.destroy()
    } catch (e: any) {
      // nop
    }
  })

  // this test should cover message handler directly without any DIDCommMessageHandler 'pre-processing'
  it('should handle brainshare post message with credential with LD proof format', async () => {
    const post = await agent.createVerifiableCredential({
      credential: {
        issuer: { id: sender.did },
        '@context': ['https://www.w3.org/2018/credentials/v1', 'custom:example.context'],
        type: ['VerifiableCredential', 'BrainSharePost'],
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          post: 'Whatever dude!',
        },
      },
      proofFormat: 'lds'
    })

    const verificationResult = await agent.verifyCredential({ credential: post })
    // console.log("LDS - verificationResult: ", verificationResult)

    const postMessage = createBrainSharePostMessage(post, sender.did, recipient.did)

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
      recipientDidUrl: recipient.did
    })
    
    const getNumCredentials2 = await agent.dataStoreORMGetVerifiableCredentialsCount()

    expect(getNumCredentials2).toEqual(getNumCredentials1 + 1)
    
    expect(res).toBeDefined()
  })

  it('should handle brainshare post message with credential with JWT proof format', async () => {
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

    const verificationResult = await agent.verifyCredential({ credential: post })
    // console.log("LDS - verificationResult: ", verificationResult)

    const postMessage = createBrainSharePostMessage(post, sender.did, recipient.did)

    const getNumCredentials1 = await agent.dataStoreORMGetVerifiableCredentialsCount()

    const packed = await agent.packDIDCommMessage({
      packing: 'authcrypt',
      message: postMessage
    })

    // const res = await agent.handleMessage({ raw: packed.message })
    // console.log("res: ", res)

    const res = await agent.sendDIDCommMessage({ 
      messageId: 'somefakeid2', 
      packedMessage: packed, 
      recipientDidUrl: recipient.did
    })
    
    const getNumCredentials2 = await agent.dataStoreORMGetVerifiableCredentialsCount()

    expect(getNumCredentials2).toEqual(getNumCredentials1 + 1)
    
    expect(res).toBeDefined()
  })

  it('should get some DID at DNS', async () => {
    const records = await getTxtRecords("nickreynolds.online")

    console.log("records: ", records)
    
  })
})
