import { IAgentContext, ICredentialPlugin, IDIDManager, IDataStore, IDataStoreORM, IKeyManager, VerifiableCredential } from '@veramo/core-types'
import { AbstractMessageHandler, Message } from '@veramo/message-handler'
import Debug from 'debug'
import { v4 } from 'uuid'
import { DIDCommMessageMediaType, IDIDComm, IDIDCommMessage } from '@veramo/did-comm'
import * as dns from 'dns'

const debug = Debug('veramo:did-comm:ml-text-generation-message-handler')

type IContext = IAgentContext<IDIDManager & IKeyManager & IDIDComm & ICredentialPlugin & IDataStore & IDataStoreORM>

/**
 * @beta
 */
export const BRAINSHARE_POST_MESSAGE_TYPE = 'https://veramo.io/didcomm/brainshare/1.0/post'

/**
 * @beta
 */
export const BRAINSHARE_REQUEST_INDEX_MESSAGE_TYPE = 'https://veramo.io/didcomm/brainshare/1.0/request-index'

/**
 * @beta
 */
export const BRAINSHARE_RETURN_INDEX_MESSAGE_TYPE = 'https://veramo.io/didcomm/brainshare/1.0/return-index'

/**
 * @beta
 */
export const BRAINSHARE_REQUEST_CREDENTIAL_MESSAGE_TYPE = 'https://veramo.io/didcomm/brainshare/1.0/request-credential'

/**
 * @beta
 */
export const BRAINSHARE_RETURN_CREDENTIAL_MESSAGE_TYPE = 'https://veramo.io/didcomm/brainshare/1.0/return-credential'

/**
 * @beta
 */
export const BRAINSHARE_CHECK_DOMAIN_LINKAGE_MESSAGE_TYPE = 'https://veramo.io/didcomm/brainshare/1.0/check-domain-linkage'

/**
 * @beta
 */
export function createBrainSharePostMessage(post: VerifiableCredential, senderDidUrl: string, recipientDidUrl: string): IDIDCommMessage {
  return {
    type: BRAINSHARE_POST_MESSAGE_TYPE,
    from: senderDidUrl,
    to: recipientDidUrl,
    id: v4(),
    body: { 
      post 
    }
  }
}

/**
 * @beta
 */
export function createBrainShareCheckDomainLinkageMessage(domain: string, senderDidUrl: string, recipientDidUrl: string): IDIDCommMessage {
  return {
    type: BRAINSHARE_CHECK_DOMAIN_LINKAGE_MESSAGE_TYPE,
    from: senderDidUrl,
    to: recipientDidUrl,
    id: v4(),
    body: {
      domain
    }
  }
}

/**
 * @beta
 */
export function createBrainShareRequestIndexMessage(senderDidUrl: string, recipientDidUrl: string): IDIDCommMessage {
  return {
    type: BRAINSHARE_REQUEST_INDEX_MESSAGE_TYPE,
    from: senderDidUrl,
    to: recipientDidUrl,
    id: v4(),
    body: {},
    return_route: 'all'
  }
}

/**
 * @beta
 */
export function createBrainShareRequestCredentialMessage(credentialHash: string, senderDidUrl: string, recipientDidUrl: string): IDIDCommMessage {
  return {
    type: BRAINSHARE_REQUEST_CREDENTIAL_MESSAGE_TYPE,
    from: senderDidUrl,
    to: recipientDidUrl,
    id: v4(),
    body: {
      credentialHash
    },
    return_route: 'all'
  }
}

/**
 * @beta
 */
export function createReturnIndexMessage(index: VerifiableCredential, hash: string, senderDidUrl: string, recipientDidUrl: string, thid: string): IDIDCommMessage {
  return {
    type: BRAINSHARE_RETURN_INDEX_MESSAGE_TYPE,
    from: senderDidUrl,
    to: recipientDidUrl,
    id: v4(),
    thid,
    body: { 
      index,
      hash
    }
  }
}

/**
 * @beta
 */
export function createReturnCredentialMessage(credential: VerifiableCredential, senderDidUrl: string, recipientDidUrl: string, thid: string): IDIDCommMessage {
  return {
    type: BRAINSHARE_RETURN_INDEX_MESSAGE_TYPE,
    from: senderDidUrl,
    to: recipientDidUrl,
    id: v4(),
    thid,
    body: { 
      credential 
    }
  }
}

export async function getTxtRecords(domain: string): Promise<any> {
  const records = await new Promise((res) => {
    dns.resolveTxt(domain, (err: any, records: any) => {
      res(records)
    })
  }) as Array<string>
  console.log("records: ", records)
  return records[0]
}

/**
 * A plugin for the {@link @veramo/message-handler#MessageHandler} that handles BrainShare messages.
 * @beta This API may change without a BREAKING CHANGE notice.
 */
export class BrainShareMessageHandler extends AbstractMessageHandler {
  constructor() {
    super()
  }

  /**
   * Handles a BrainShare Message
   * https://github.com/veramolabs/BrainShareProtocol/
   */
  public async handle(message: Message, context: IContext): Promise<Message> {
    if (message.type === BRAINSHARE_POST_MESSAGE_TYPE) {
      debug('BrainShare Post Message Received')
      try {
        const { from, to, data } = message
        if (!from) {
          throw new Error("invalid_argument: BrainShare Message received without `from` set")
        }
        if (!to) {
          throw new Error("invalid_argument: BrainShare Message received without `to` set")
        }
        if (!data.post) {
          throw new Error("invalid_argument: BrainShare Message received without `body.post` set")
        }

        const verificationResult = await context.agent.verifyCredential({ credential: data.post })
        if (verificationResult.verified) {
          debug("BrainShare Post Message Verified.")
          // TODO: check type, other things
          await context.agent.dataStoreSaveVerifiableCredential({ verifiableCredential: data.post })
        }

        message.addMetaData({ type: 'BrainShare Post', value: 'saved' })
      } catch (ex) {
        debug(ex)
      }
      // return message
      return message
    } else if (message.type === BRAINSHARE_CHECK_DOMAIN_LINKAGE_MESSAGE_TYPE) {
      const { from, to, data } = message
      if (!from) {
        throw new Error("invalid_argument: BrainShare Domain Linkage Message received without `from` set")
      }
      if (!to) {
        throw new Error("invalid_argument: BrainShare Domain Linkage Message received without `to` set")
      }
      if (!data.domain) {
        throw new Error("invalid_argument: BrainShare Domain Linkage Message received without `body.domain` set")
      }

      const records = await getTxtRecords("_brainshare." + data.domain)

      if (records && records.length > 0 && records[0] === from) {
        // TODO: delete any old creds

        // create & save BrainShareDomainLinkageCredential
        const cred = await context.agent.createVerifiableCredential({
          credential: {
            issuer: { id: to },
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiableCredential', 'BrainShareDomainLinkage'],
            issuanceDate: new Date().toISOString(),
            credentialSubject: {
              id: from,
              domain: data.domain
            },
          },
          proofFormat: 'jwt'
        })

        await context.agent.dataStoreSaveVerifiableCredential({ verifiableCredential: cred })
      }
      return message
    } else if (message.type === BRAINSHARE_REQUEST_CREDENTIAL_MESSAGE_TYPE) {
      const { from, to, data } = message
      if (!from) {
        throw new Error("invalid_argument: BrainShare Message received without `from` set")
      }
      if (!to) {
        throw new Error("invalid_argument: BrainShare Message received without `to` set")
      }

      const cred = await context.agent.dataStoreGetVerifiableCredential({ hash: data.hash })
      if (cred && cred.credentialSubject.shouldBeIndexed) {
        const response = createReturnCredentialMessage(cred, from, to, message.id)
        const packedResponse = await context.agent.packDIDCommMessage({
          message: response,
          packing: 'authcrypt',
        })
        const returnResponse = {
          id: response.id,
          message: packedResponse.message,
          contentType: DIDCommMessageMediaType.ENCRYPTED,
        }
        message.addMetaData({ type: 'ReturnRouteResponse', value: JSON.stringify(returnResponse) })
      } else {
        // should return problem report
      }
    } else if (message.type === BRAINSHARE_REQUEST_INDEX_MESSAGE_TYPE) {
      const { from, to, returnRoute } = message
      debug("Index Requested. Recipient: " + to)
      if (!from) {
        throw new Error("invalid_argument: BrainShare Message received without `from` set")
      }
      if (!to) {
        throw new Error("invalid_argument: BrainShare Message received without `to` set")
      }

      const numCreds1  = await context.agent.dataStoreORMGetVerifiableCredentialsCount()
      const indexCred = await context.agent.dataStoreORMGetVerifiableCredentials({
        where: [{ column: 'issuer', value: [to] }, { column: 'type', value: ['VerifiableCredential,BrainShareIndex']}],
        order: [{ column: 'issuanceDate', direction: 'DESC' }],
        take: 1
      })
      if (indexCred && indexCred.length > 0) {
        const response = createReturnIndexMessage(indexCred[0].verifiableCredential, indexCred[0].hash, from, to, message.id)
        const packedResponse = await context.agent.packDIDCommMessage({
          message: response,
          packing: 'authcrypt',
        })
        const returnResponse = {
          id: response.id,
          message: packedResponse.message,
          contentType: DIDCommMessageMediaType.ENCRYPTED,
        }
        if (returnRoute === 'all') {
          message.addMetaData({ type: 'ReturnRouteResponse', value: JSON.stringify(returnResponse) })
        } else {
          await context.agent.sendDIDCommMessage({
            messageId: returnResponse.id,
            packedMessage: packedResponse,
            recipientDidUrl: from
          })
        }
      } else {
        // should return problem report
      }
    }

    return super.handle(message, context)
  }
}
