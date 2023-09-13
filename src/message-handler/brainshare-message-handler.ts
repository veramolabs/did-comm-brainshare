import { IAgentContext, ICredentialPlugin, IDIDManager, IDataStore, IKeyManager, VerifiableCredential } from '@veramo/core-types'
import { AbstractMessageHandler, Message } from '@veramo/message-handler'
import Debug from 'debug'
import { v4 } from 'uuid'
import { IDIDComm, IDIDCommMessage } from '@veramo/did-comm'

const debug = Debug('veramo:did-comm:ml-text-generation-message-handler')

type IContext = IAgentContext<IDIDManager & IKeyManager & IDIDComm & ICredentialPlugin & IDataStore>

/**
 * @beta
 */
export const BRAINSHARE_POST_MESSAGE_TYPE = 'https://veramo.io/didcomm/brainshare/1.0/post'

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
    body: post
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
 * A plugin for the {@link @veramo/message-handler#MessageHandler} that handles BrainShare messages.
 * @beta This API may change without a BREAKING CHANGE notice.
 */
export class BrainShareMessageHandler extends AbstractMessageHandler {
  constructor() {
    super()
  }

  /**
   * Handles a BrainShare Post Message
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
          // TODO: check type, other things
          await context.agent.dataStoreSaveVerifiableCredential({ verifiableCredential: data.post })
        }

        message.addMetaData({ type: 'BrainShare Post', value: 'saved' })
      } catch (ex) {
        debug(ex)
      }
      return message
    }

    return super.handle(message, context)
  }
}
