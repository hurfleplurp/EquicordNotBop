/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { ChatBarButton, ChatBarButtonFactory } from "@api/ChatButtons";
import { ApplicationCommandInputType, ApplicationCommandOptionType, findOption, sendBotMessage } from "@api/Commands";
import * as DataStore from "@api/DataStore";
import { definePluginSettings } from "@api/Settings";
import { Button } from "@components/Button";
import { sendMessage } from "@utils/discord";
import { Logger } from "@utils/Logger";
import { ModalCloseButton, ModalContent, ModalFooter, ModalHeader, ModalProps, ModalRoot, openModal } from "@utils/modal";
import definePlugin, { OptionType } from "@utils/types";
import { ChannelStore, FluxDispatcher, MessageStore, React, SelectedChannelStore, TextInput, Toasts, UserStore, useState } from "@webpack/common";

// Helper function to show toast notifications
const showToast = (message: string, type: typeof Toasts.Type[keyof typeof Toasts.Type] = Toasts.Type.MESSAGE): void => {
    // Create a properly typed toast options object
    const toastOptions = {
        message,
        id: Toasts.genId(),
        type, // Use the enum value directly
        options: {
            position: Toasts.Position.BOTTOM
        }
    } as const;
    // Show the toast with the properly typed options
    Toasts.show(toastOptions as any); // Type assertion to handle the Discord.js toast type
};



type CommandReturnValue = { content: string; } | void;
type CommandHandler = (args: any[], ctx: any) => Promise<CommandReturnValue>;

const logger = new Logger("AiResponder");
const API_KEY_STORE_KEY = "AiResponder_apiKey";
const SYSTEM_PROMPTS_STORE_KEY = "AiResponder_systemPrompts";
const AUTO_REPLY_STORE_KEY = "AiResponder_autoReplyChannels";
const CHAT_CONTEXTS_STORE_KEY = "AiResponder_chatContexts";

let autoReplyChannels: Set<string> = new Set();
const pendingReplies: Record<string, number> = {};
const pendingContexts: Record<string, string> = {};
const pendingResponses: Record<string, {
    abortController: AbortController;
    timeoutId?: number;
    typingInterval?: number;
    typingStartTime: number;
}> = {};

// Typing indicator constants
const TYPING_INDICATOR_DURATION = 8000; // 8 seconds
const TYPING_INDICATOR_INTERVAL = 5000; // 5 seconds

// Helper function to create command handlers with proper typing
function makeCommandHandler(handler: CommandHandler): CommandHandler {
    return async (args, ctx) => {
        try {
            return await handler(args, ctx);
        } catch (error) {
            logger.error("Command error:", error);
            sendBotMessage(ctx.channel.id, { content: "❌ An error occurred while executing this command." });
        }
    };
}

interface SystemPrompt {
    name: string;
    prompt: string;
}

// Interface for chat contexts
interface ChatContexts {
    [channelId: string]: string;
}

// Helper function to get chat contexts
async function getChatContexts(): Promise<ChatContexts> {
    const stored = await DataStore.get(CHAT_CONTEXTS_STORE_KEY);
    return stored || {};
}

// Helper function to save chat contexts
async function saveChatContexts(contexts: ChatContexts): Promise<void> {
    await DataStore.set(CHAT_CONTEXTS_STORE_KEY, contexts);
}

// Function to get context for a specific chat
async function getChatContext(channelId: string): Promise<string> {
    const contexts = await getChatContexts();
    return contexts[channelId] || "";
}

// Function to set context for a specific chat
async function setChatContext(channelId: string, context: string): Promise<void> {
    const contexts = await getChatContexts();
    if (context.trim()) {
        contexts[channelId] = context;
    } else {
        delete contexts[channelId];
    }
    await saveChatContexts(contexts);
}



const settings = definePluginSettings({
    apiKey: {
        type: OptionType.STRING,
        description: "OpenAI API Key",
        default: "",
        placeholder: "sk-..."
    },
    activePrompt: {
        type: OptionType.STRING,
        description: "Active character prompt name",
        default: "default"
    },
    maxMessages: {
        type: OptionType.SLIDER,
        description: "Maximum number of messages to include in context",
        default: 10,
        markers: [5, 10, 15, 20, 25],
        stickToMarkers: false
    },
    keybind: {
        type: OptionType.STRING,
        description: "Keybind to trigger AI response (format: Ctrl+Alt+R)",
        default: "Ctrl+Alt+R"
    },
    model: {
        type: OptionType.SELECT,
        description: "AI model to use",
        options: [
            { label: "Qwen 235B", value: "qwen3-235b", default: true },
            { label: "Qwen 4B", value: "qwen3-4b" },
            { label: "Qwen 2.5 QWQ 32B", value: "qwen-2.5-qwq-32b" },
            { label: "Venice Uncensored", value: "venice-uncensored" }
        ]
    },
    hideThinkingBlocks: {
        type: OptionType.BOOLEAN,
        description: "Hide thinking/reasoning blocks from responses (uses strip_thinking_response=true)",
        default: true
    },
    maxRetries: {
        type: OptionType.SLIDER,
        description: "Maximum retry attempts for incomplete responses",
        default: 2,
        markers: [1, 2, 3, 4, 5],
        stickToMarkers: false
    },
    incompleteResponseThreshold: {
        type: OptionType.SLIDER,
        description: "Minimum response length to consider complete (characters)",
        default: 50,
        markers: [25, 50, 100, 200],
        stickToMarkers: false
    },
    enableRetries: {
        type: OptionType.BOOLEAN,
        description: "Enable automatic retries for incomplete responses",
        default: true
    }
});

async function getApiKey(): Promise<string | null> {
    const stored = await DataStore.get(API_KEY_STORE_KEY);
    return stored || settings.store.apiKey || null;
}

async function setApiKey(key: string): Promise<void> {
    await DataStore.set(API_KEY_STORE_KEY, key);
}

function ApiKeyModal({ modalProps, initialValue, onSubmit }: { modalProps: ModalProps; initialValue: string; onSubmit: (value: string | null) => void; }) {
    const [value, setValue] = useState(initialValue);

    return (
        <ModalRoot {...modalProps}>
            <ModalHeader>
                <div style={{ flexGrow: 1, fontWeight: 600 }}>
                    Set API Key
                </div>
                <ModalCloseButton onClick={() => {
                    onSubmit(null);
                    modalProps.onClose();
                }} />
            </ModalHeader>
            <ModalContent>
                <TextInput
                    value={value}
                    onChange={setValue}
                    placeholder="sk-..."
                    style={{ width: "100%" }}
                />
            </ModalContent>
            <ModalFooter>
                <Button
                    variant="primary"
                    onClick={() => {
                        const trimmed = value.trim();
                        onSubmit(trimmed || null);
                        modalProps.onClose();
                    }}
                >
                    Save
                </Button>
                <Button
                    variant="secondary"
                    style={{ marginRight: "8px" }}
                    onClick={() => {
                        onSubmit(null);
                        modalProps.onClose();
                    }}
                >
                    Cancel
                </Button>
            </ModalFooter>
        </ModalRoot>
    );
}

function openApiKeyModal(initialValue = ""): Promise<string | null> {
    return new Promise(resolve => {
        let settled = false;
        const settleOnce = (value: string | null) => {
            if (settled) return;
            settled = true;
            resolve(value);
        };

        openModal(
            props => <ApiKeyModal modalProps={props} initialValue={initialValue} onSubmit={settleOnce} />,
            {
                onCloseCallback: () => settleOnce(null)
            }
        );
    });
}

async function getSystemPrompts(): Promise<SystemPrompt[]> {
    const stored = await DataStore.get(SYSTEM_PROMPTS_STORE_KEY);
    return stored || [
        {
            name: "default",
            prompt: "You are the current userresponding in Discord. Paying attention to the chat history, continue responding in the same style."
        },
        {
            name: "roadman",
            prompt: "You are a sharp-tongued South London roadman with a shaved head, hollow cheekbones, and a perpetual sneer, wears a navy Stone Island tracksuit with the zip half-up, revealing a gold chain dangling over a faded band tee; his arms are sleeved in barbed-wire tattoos, fingers adorned with oversized rings spelling 'ENDZ' and 'BLOK,' while aviators shield his restless eyes even indoors; he speaks in clipped, venomous cockney-Caribbean slang ('You ain’t from here, bruv—endz only'), cracks his knuckles habitually, and carries a battered iPhone with a cracked screen in one hand, a roll-up cigarette in the other, always lurking near a graffiti-tagged car park or kebab van, where he trades whispers about the block and flexes loyalty to his crew like armor."
        },
        {
            name: "egirl",
            prompt: "You are a bubbly yet edgy streamer with pastel-dyed hair (half-pink half-black) and a smudge of temporary glitter under one eye, sits cross-legged on a gaming chair in a dimly lit room plastered with Dorado map posters and LED strips; she wears a cropped hoodie with the Overwatch logo, fingerless gloves, and a choker with a tiny Tracer pendant, her mic-arm headset glowing neon as she taunts enemies in a sing-song voice ('Bye-bye, Reaper!'), sips bubble tea, and mutes her chat’s POV you’re the 6th man' jokes mid-solo Lucio clutch, her screen reflecting off round anime-themed glasses while a plush Mercy doll hangs from her monitor."
        }
    ];
}

async function saveSystemPrompts(prompts: SystemPrompt[]): Promise<void> {
    await DataStore.set(SYSTEM_PROMPTS_STORE_KEY, prompts);
}

/* ---------- Auto-Reply Utilities ---------- */
async function getAutoReplyChannels(): Promise<Set<string>> {
    const stored = await DataStore.get(AUTO_REPLY_STORE_KEY);
    return new Set(stored || []);
}

async function saveAutoReplyChannels(channels: Set<string>): Promise<void> {
    await DataStore.set(AUTO_REPLY_STORE_KEY, Array.from(channels));
}

function sampleDelayMs(): number {
    // Normal distribution N(20s, 10s²) truncated to [0,60] seconds
    let u = 0, v = 0;
    while (u === 0) u = Math.random();
    while (v === 0) v = Math.random();
    const stdNormal = Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
    let delaySec = 20 + 10 * stdNormal;
    delaySec = Math.max(0, Math.min(60, delaySec));
    return delaySec * 1000;
}

// Function to start typing indicators
function startTypingIndicator(channelId: string): number | undefined {
    if (!ChannelStore.getChannel(channelId)) return;
    // Start typing
    FluxDispatcher.dispatch({
        type: "TYPING_START",
        channelId,
        userId: UserStore.getCurrentUser().id
    });

    // Set up interval to keep typing active
    const typingInterval = setInterval(() => {
        if (!pendingResponses[channelId]) return;

        // Check if we should stop typing (after 8 seconds of inactivity)
        const timeSinceLastTyping = Date.now() - (pendingResponses[channelId]?.typingStartTime || 0);
        if (timeSinceLastTyping > TYPING_INDICATOR_DURATION) {
            stopTypingIndicator(channelId);
            return;
        }

        // Keep typing active
        FluxDispatcher.dispatch({
            type: "TYPING_START",
            channelId,
            userId: UserStore.getCurrentUser().id
        });
    }, TYPING_INDICATOR_INTERVAL) as unknown as number;

    return typingInterval;
}

// Function to stop typing indicators
function stopTypingIndicator(channelId: string) {
    if (!pendingResponses[channelId]) return;

    clearInterval(pendingResponses[channelId].typingInterval);

    // Only stop typing if we're not in the middle of a response
    if (!pendingResponses[channelId].abortController.signal.aborted) {
        FluxDispatcher.dispatch({
            type: "TYPING_STOP",
            channelId,
            userId: UserStore.getCurrentUser().id
        });
    }
}

async function autoReply(channelId: string) {
    try {
        // Calculate delay based on message length (capped at 60s for 500+ chars)
        const calculateTypingDelay = (text: string): number => {
            const baseDelay = 1000; // 1 second minimum
            const charDelay = Math.min(text.length * 120, 60000); // 120ms per char, max 60s
            return baseDelay + charDelay;
        };

        // Add a small delay before starting to show typing indicator
        await new Promise(resolve => setTimeout(resolve, 500));

        // Start typing indicator (will be stored in pendingResponses by generateAiResponse)
        const typingInterval = startTypingIndicator(channelId);

        // Generate response and calculate typing delay
        const responseText = await generateAiResponse(channelId);

        // Store typing interval after response generation creates the pendingResponses entry
        if (typingInterval !== undefined && pendingResponses[channelId]) {
            pendingResponses[channelId].typingInterval = typingInterval;
        }

        // Stop typing indicators if they're still active
        if (pendingResponses[channelId]) {
            stopTypingIndicator(channelId);
        }

        if (!responseText) return;

        // Calculate typing delay and wait
        const typingDelay = calculateTypingDelay(responseText);
        await new Promise(resolve => setTimeout(resolve, typingDelay));

        // Send the message using the available method
        try {
            await sendMessage(channelId, { content: responseText });
            logger.log("Message sent successfully via auto-reply");
        } catch (error) {
            logger.error("Failed to send message:", error);
            showToast("Failed to send auto-reply message", Toasts.Type.FAILURE);
        }
    } catch (err) {
        logger.error("Auto-reply failed:", err);
        showToast("Auto-reply failed", Toasts.Type.FAILURE);
    } finally {
        // Ensure typing indicators are cleaned up
        if (pendingResponses[channelId]) {
            stopTypingIndicator(channelId);
            delete pendingResponses[channelId];
        }
    }
}

function handleIncomingMessage({ message }: { message: any; }) {
    if (!message || message.author?.id === UserStore.getCurrentUser().id) return;
    const channel = ChannelStore.getChannel(message.channel_id);
    if (!channel || (channel.type !== 1 && channel.type !== 3)) return; // DM or Group DM only
    if (!autoReplyChannels.has(channel.id)) return;
    if (pendingReplies[channel.id]) return; // already scheduled

    const delay = sampleDelayMs();
    pendingReplies[channel.id] = window.setTimeout(async () => {
        delete pendingReplies[channel.id];
        await autoReply(channel.id);
    }, delay);
}

async function getChatHistory(channelId: string, limit: number): Promise<any[]> {
    const messages = MessageStore.getMessages(channelId)._array || [];
    return messages
        .filter(msg => !msg.deleted && msg.content)
        .slice(-limit)
        .map(msg => ({
            role: msg.author.id === UserStore.getCurrentUser().id ? "assistant" : "user",
            content: `${msg.author.username}: ${msg.content}`,
            timestamp: msg.timestamp
        }));
}

// Helper function to detect incomplete responses
function isResponseIncomplete(response: string, threshold: number): boolean {
    // Check if response is too short
    if (response.trim().length < threshold) {
        return true;
    }

    // Check for incomplete thinking blocks (missing closing tags)
    if (response.includes("<think>")) {
        const openTags = (response.match(/<think>/g) || []).length;
        const closeTags = (response.match(/<\/think>/g) || []).length;

        // If we have more open tags than close tags, response is incomplete
        if (openTags > closeTags) {
            return true;
        }
    }

    // Check for unclosed code blocks
    const codeBlocks = response.match(/```/g);
    if (codeBlocks && codeBlocks.length % 2 !== 0) {
        return true;
    }

    // Check for incomplete parentheses or brackets
    const openParens = (response.match(/\(/g) || []).length;
    const closeParens = (response.match(/\)/g) || []).length;
    const openBrackets = (response.match(/\[/g) || []).length;
    const closeBrackets = (response.match(/\]/g) || []).length;
    const openBraces = (response.match(/\{/g) || []).length;
    const closeBraces = (response.match(/\}/g) || []).length;

    if (openParens !== closeParens || openBrackets !== closeBrackets || openBraces !== closeBraces) {
        return true;
    }

    // Check if response ends with incomplete sentence (no proper punctuation)
    const trimmed = response.trim();
    if (!/[:;,.!?\-)]$/.test(trimmed)) {
        // Allow ending with quotes, but check if they're balanced
        const quotes = (trimmed.match(/"/g) || []).length;
        if (quotes % 2 !== 0) {
            return true;
        }
    }

    return false;
}



async function generateAiResponse(channelId: string, retryCount = 0, existingController?: AbortController): Promise<string> {
    try {
        logger.log("Starting AI response generation...");
        const apiKey = await getApiKey();
        if (!apiKey) {
            throw new Error("No API key configured. Please set your OpenAI API key first.");
        }

        logger.log("Fetching system prompts...");
        const prompts = await getSystemPrompts();
        const activePrompt = prompts.find(p => p.name === settings.store.activePrompt);
        if (!activePrompt) {
            throw new Error(`System prompt "${settings.store.activePrompt}" not found.`);
        }

        logger.log("Getting chat history...");
        const history = await getChatHistory(channelId, settings.store.maxMessages);
        const currentUser = UserStore.getCurrentUser();

        // Get chat-specific context
        const chatContext = await getChatContext(channelId);
        const oneOffContext = pendingContexts[channelId] || "";

        // Clear one-off context after use
        if (pendingContexts[channelId]) {
            delete pendingContexts[channelId];
        }

        const systemMessage = `${activePrompt.prompt}

${chatContext ? `CONTEXT FOR THIS CHAT: ${chatContext}\n\n` : ""}${oneOffContext ? `ADDITIONAL INSTRUCTIONS: ${oneOffContext}\n\n` : ""}IMPORTANT INSTRUCTIONS:
1. You are responding as ${currentUser.username} in this Discord conversation.
2. The conversation history will be provided for context.
3. DO NOT include anything between <think></think> tags.
4. DO NOT use phrases like "I think...", "Let me...", or any other meta-commentary.
5. ONLY respond with the direct message content you want to send.
6. Keep responses concise and to the point, verbose replies are not convincing natural conversation.
7. DO NOT roleplay in italics in your reply.
8. Only use emotes if absolutely appropriate, use sparingly.`;

        const messages = [
            {
                role: "system",
                content: systemMessage
            },
            ...history.map(msg => ({
                role: msg.role === "assistant" ? "assistant" : "user",
                content: msg.content
            }))
        ];

        logger.log(`Sending request to Venice AI API with model: ${settings.store.model}`);

        const requestBody = {
            frequency_penalty: 0,
            n: 1,
            presence_penalty: 0,
            temperature: 0.7,
            top_p: 0.9,
            venice_parameters: {
                include_venice_system_prompt: true,
                strip_thinking_response: settings.store.hideThinkingBlocks
            },
            parallel_tool_calls: true,
            model: settings.store.model,
            messages,
            stop: ["</s>", "```"]
        };

        // Create abort controller if not provided
        const controller = existingController || new AbortController();
        // Store the abort controller for potential cancellation
        if (!existingController) {
            // Clear any existing pending response for this channel
            if (pendingResponses[channelId]) {
                clearTimeout(pendingResponses[channelId].timeoutId);
                clearInterval(pendingResponses[channelId].typingInterval);
            }
            pendingResponses[channelId] = {
                abortController: controller,
                typingStartTime: Date.now()
            };
        }

        try {
            const response = await fetch("https://api.venice.ai/api/v1/chat/completions", {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${apiKey}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(requestBody),
                signal: controller.signal
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error?.message || `API request failed with status ${response.status}`);
            }

            const data = await response.json();
            let responseText = data.choices?.[0]?.message?.content?.trim();

            if (!responseText) {
                throw new Error("Empty response from API");
            }

            // Check if response is complete
            if (settings.store.enableRetries &&
                retryCount < settings.store.maxRetries &&
                isResponseIncomplete(responseText, settings.store.incompleteResponseThreshold)) {
                logger.log(`Response appears incomplete, retrying (attempt ${retryCount + 1}/${settings.store.maxRetries})`);
                return generateAiResponse(channelId, retryCount + 1, controller);
            }

            // Clean up the response
            responseText = cleanAiResponse(responseText);
            logger.log("Cleaned AI Response Content:", responseText);

            if (!responseText) {
                throw new Error("Received empty response after cleaning");
            }

            return responseText;
        } catch (error: unknown) {
            const err = error as Error & { name: string; };
            if (err.name === "AbortError") {
                logger.log("AI response generation was aborted");
                throw err;
            }

            logger.error("Error generating AI response:", err);
            if (retryCount < settings.store.maxRetries) {
                logger.log(`Retrying... (${retryCount + 1}/${settings.store.maxRetries})`);
                return generateAiResponse(channelId, retryCount + 1, controller);
            }
            throw error;
        } finally {
            // Clean up pending response if this was the original call
            if (!existingController && pendingResponses[channelId]) {
                delete pendingResponses[channelId];
            }
        }
    } catch (error) {
        logger.error("Error in generateAiResponse:", error);
        if (error instanceof Error) {
            throw error;
        }
        throw new Error(String(error));
    }
}

function cleanAiResponse(text: string): string {
    // Remove content between <think> tags
    let cleaned = text.replace(/<think>[\s\S]*?<\/think>/g, "");

    // Remove any username: at the start of the message
    cleaned = cleaned.replace(/^\s*\w+\s*:\s*/, "");

    // Remove any trailing text like "thottweiler:" or other bot names followed by colon
    cleaned = cleaned.replace(/\s*\b\w+:$/g, "").trim();

    // Remove any remaining HTML-like tags
    cleaned = cleaned.replace(/<[^>]*>?/gm, "");

    return cleaned || "";
}

async function insertTextDirectly(text: string): Promise<void> {
    try {
        // Try to find the chat input using various selectors, prioritizing the rich text editor
        const selectors = [
            // Rich text editor in main chat
            "div[class*='slateTextArea_'][contenteditable='true']",
            // Fallback selectors
            "[role='textbox'][contenteditable='true']",
            "div[class*='textArea_'] [contenteditable='true']",
            "[contenteditable='true']",
            // Legacy selectors
            "textarea[aria-label*='Send a message']",
            "div[class*='textArea_'] textarea",
            "textarea[class*='textArea_']"
        ];

        for (const selector of selectors) {
            const elements = document.querySelectorAll(selector);
            if (elements.length === 0) continue;

            logger.log(`Trying selector: ${selector}, found ${elements.length} elements`);

            for (const element of elements) {
                try {
                    const input = element as HTMLElement;
                    input.focus();

                    // For rich text editor (Slate.js)
                    if (input.getAttribute("data-slate-editor") === "true") {
                        logger.log("Found Slate.js editor, using execCommand");

                        try {
                            // Try to find the hidden textarea inside the composer
                            const textarea = input.parentElement?.querySelector("textarea");
                            if (textarea) {
                                logger.log("Found hidden textarea inside composer, using value property");
                                (textarea as HTMLTextAreaElement).focus();
                                (textarea as HTMLTextAreaElement).value = text;
                                textarea.dispatchEvent(new Event("input", { bubbles: true }));
                                textarea.dispatchEvent(new Event("change", { bubbles: true }));
                                logger.log("Successfully inserted text via hidden textarea");
                                return;
                            }

                            // Fallback: use execCommand
                            input.focus();
                            const range = document.createRange();
                            range.selectNodeContents(input);
                            range.collapse(false);
                            const selection = window.getSelection();
                            selection?.removeAllRanges();
                            selection?.addRange(range);

                            const success = document.execCommand("insertText", false, text);
                            logger.log(`execCommand('insertText') returned: ${success}`);
                            input.dispatchEvent(new Event("input", { bubbles: true }));
                            input.dispatchEvent(new Event("change", { bubbles: true }));
                            return;
                        } catch (error) {
                            logger.error("Error in Slate.js editor insertion:", error);
                            // Fall through to clipboard method
                        }
                    }
                    // For regular textareas
                    else if ("value" in input) {
                        logger.log("Found textarea, using value property");
                        const textarea = input as HTMLTextAreaElement;
                        const start = textarea.selectionStart || 0;
                        const end = textarea.selectionEnd || 0;
                        const currentValue = textarea.value;
                        textarea.value = currentValue.substring(0, start) + text + currentValue.substring(end);
                        textarea.dispatchEvent(new Event("input", { bubbles: true }));
                        textarea.dispatchEvent(new Event("change", { bubbles: true }));
                        logger.log("Successfully inserted text into textarea");
                        return;
                    }
                    // For other contenteditable elements
                    else if (input.isContentEditable) {
                        logger.log("Found contenteditable element, using execCommand");
                        const range = document.createRange();
                        const selection = window.getSelection();
                        range.selectNodeContents(input);
                        range.collapse(false);
                        selection?.removeAllRanges();
                        selection?.addRange(range);
                        document.execCommand("insertText", false, text);
                        logger.log("Successfully inserted text using execCommand");
                        return;
                    }

                    logger.log(`Text inserted using selector: ${selector}`);
                    return;
                } catch (error) {
                    logger.log(`Failed with selector ${selector}:`, error);
                    continue;
                }
            }
        }

        // If we get here, all selectors failed
        logger.error("All text insertion methods failed");

        // As a last resort, copy to clipboard and show a toast
        try {
            await navigator.clipboard.writeText(text);
            showToast("Response copied to clipboard. Use Ctrl+V to paste.", Toasts.Type.MESSAGE);
            logger.log("Response copied to clipboard as fallback");
        } catch (clipboardError) {
            logger.error("Failed to copy to clipboard:", clipboardError);
            throw new Error("Could not insert text into chat or copy to clipboard");
        }
    } catch (error) {
        logger.error("Error in insertTextDirectly:", error);
        throw error;
    }
}

async function handleAiResponse(insertMode = false) {
    const channelId = SelectedChannelStore.getChannelId();
    if (!channelId) {
        showToast("No channel selected", Toasts.Type.MESSAGE);
        return;
    }

    try {
        showToast("Generating AI response...", Toasts.Type.MESSAGE);
        logger.log("Starting AI response generation...");

        let response = await generateAiResponse(channelId);
        logger.log("AI response generated successfully");

        // Clean up the response
        response = cleanAiResponse(response);
        logger.log("Cleaned AI Response Content:", response);

        if (!response) {
            throw new Error("Received empty response after cleaning");
        }

        if (insertMode) {
            logger.log("Sending response as user message");
            await sendMessage(channelId, { content: response });
        } else {
            logger.log("Sending response as bot message");
            try {
                // Send the bot message properly
                sendBotMessage(channelId, {
                    content: response
                });
                showToast("AI response sent successfully", Toasts.Type.SUCCESS);
            } catch (error) {
                logger.error("Failed to send message with sendBotMessage:", error);
                // Fallback to using the chat input box
                logger.log("Falling back to chat input box");
                await insertTextDirectly(response);
            }
        }

        logger.log("AI response handling complete");
        showToast("AI response generated!", Toasts.Type.SUCCESS);
    } catch (error: any) {
        const errorMessage = error?.message || "Unknown error occurred";
        logger.error("Failed to handle AI response:", error);
        showToast(`Error: ${errorMessage}`, Toasts.Type.FAILURE);
    }
}

const AiResponderButton: ChatBarButtonFactory = ({ isMainChat }) => {
    if (!isMainChat) return null;

    return (
        <ChatBarButton
            tooltip="Generate AI Response (Right-click for preview)"
            onClick={() => handleAiResponse(true)}
            onContextMenu={e => {
                e.preventDefault();
                handleAiResponse(false); // Preview mode on right-click
            }}
        >
            <svg
                width="24"
                height="24"
                viewBox="0 0 24 24"
                fill="currentColor"
            >
                <path d="M12 2C17.52 2 22 6.48 22 12C22 17.52 17.52 22 12 22C6.48 22 2 17.52 2 12C2 6.48 6.48 2 12 2ZM18 12H14L16 10V7H8V10L10 12H6L10 16H14L18 12Z" />
            </svg>
        </ChatBarButton>
    );
};

function parseKeybind(keybind: string) {
    const parts = keybind.toLowerCase().split("+");
    return {
        ctrl: parts.includes("ctrl"),
        alt: parts.includes("alt"),
        shift: parts.includes("shift"),
        key: parts[parts.length - 1]
    };
}

function handleKeyDown(event: KeyboardEvent) {
    const keybind = parseKeybind(settings.store.keybind);

    if (
        event.ctrlKey === keybind.ctrl &&
        event.altKey === keybind.alt &&
        event.shiftKey === keybind.shift &&
        event.key.toLowerCase() === keybind.key
    ) {
        event.preventDefault();
        handleAiResponse(true);
    }
}

export default definePlugin({
    name: "AiResponder",
    description: "Responds to messages using AI with customizable characters and chat history context",
    authors: [{ name: "Sufo", id: 1234567890n }],
    settings,

    renderChatBarButton: AiResponderButton,

    commands: [
        {
            name: "ai-respond",
            description: "Generate an AI response",
            inputType: ApplicationCommandInputType.BUILT_IN,
            options: [
                {
                    name: "mode",
                    description: "Response mode",
                    type: ApplicationCommandOptionType.STRING,
                    choices: [
                        { name: "Insert to chat", label: "Insert to chat", value: "insert" },
                        { name: "Preview only", label: "Preview only", value: "preview" }
                    ]
                }
            ],
            execute: async (args, ctx) => {
                const mode = findOption(args, "mode", "insert");
                await handleAiResponse(mode === "insert");
            }
        },
        {
            name: "ai-set-key",
            description: "Set your OpenAI API key",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: async (_, ctx) => {
                const existing = await getApiKey();
                const key = await openApiKeyModal(existing ?? "");
                if (!key) return;

                await setApiKey(key);
                sendBotMessage(ctx.channel.id, {
                    content: "✅ API key saved successfully!"
                });
            }
        },

        {
            name: "ai-view-prompt",
            description: "View the contents of a system prompt",
            inputType: ApplicationCommandInputType.BUILT_IN,
            options: [
                {
                    name: "name",
                    description: "Name of the prompt to view",
                    type: ApplicationCommandOptionType.STRING,
                    required: true
                }
            ],
            execute: makeCommandHandler(async (args, ctx) => {
                const promptName = findOption(args, "name");
                if (!promptName) {
                    sendBotMessage(ctx.channel.id, { content: "❌ Please specify a prompt name to view." }); return;
                }

                try {
                    const prompts = await getSystemPrompts();
                    const prompt = prompts.find(p => p.name === promptName);

                    if (!prompt) {
                        sendBotMessage(ctx.channel.id, { content: `❌ No prompt found with name "${promptName}".` }); return;
                    }

                    // Format the response to show the prompt content in a code block
                    // and prevent mention parsing by using backticks
                    const formattedContent = prompt.prompt.replace(/`/g, "`");
                    return {
                        content: `**Prompt: ${prompt.name}**\n\`\`\`\n${formattedContent}\n\`\`\``
                    };
                } catch (error) {
                    logger.error("Failed to view prompt:", error);
                    sendBotMessage(ctx.channel.id, { content: "❌ An error occurred while trying to view the prompt." }); return;
                }
            })
        },
        {
            name: "ai-add-prompt",
            description: "Add or update a custom system prompt",
            inputType: ApplicationCommandInputType.BUILT_IN,
            options: [
                {
                    name: "name",
                    description: "Name for the prompt (e.g., 'pirate', 'professional')",
                    type: ApplicationCommandOptionType.STRING,
                    required: true
                },
                {
                    name: "prompt",
                    description: "The system prompt text describing how the AI should behave",
                    type: ApplicationCommandOptionType.STRING,
                    required: true
                }
            ],
            execute: makeCommandHandler(async (args, ctx) => {
                const name = findOption(args, "name") as string;
                const promptText = findOption(args, "prompt") as string;

                if (!name || !promptText) {
                    sendBotMessage(ctx.channel.id, { content: "❌ Please provide both a name and prompt text." });
                    return;
                }

                // Validate name format (alphanumeric and hyphens only)
                if (!/^[a-zA-Z0-9-_]+$/.test(name)) {
                    sendBotMessage(ctx.channel.id, { content: "❌ Prompt name can only contain letters, numbers, hyphens, and underscores." });
                    return;
                }

                try {
                    const prompts = await getSystemPrompts();
                    const existingIndex = prompts.findIndex(p => p.name === name);

                    if (existingIndex >= 0) {
                        // Update existing prompt
                        prompts[existingIndex].prompt = promptText;
                        await saveSystemPrompts(prompts);
                        sendBotMessage(ctx.channel.id, { content: `✅ Updated existing prompt "${name}".` });
                    } else {
                        // Add new prompt
                        prompts.push({ name, prompt: promptText });
                        await saveSystemPrompts(prompts);
                        sendBotMessage(ctx.channel.id, { content: `✅ Added new prompt "${name}". Use /ai-set-active ${name} to activate it.` });
                    }
                } catch (error) {
                    logger.error("Failed to add prompt:", error);
                    sendBotMessage(ctx.channel.id, { content: "❌ An error occurred while trying to add the prompt." });
                }
            })
        },
        {
            name: "ai-delete-prompt",
            description: "Delete a custom system prompt",
            inputType: ApplicationCommandInputType.BUILT_IN,
            options: [
                {
                    name: "name",
                    description: "Name of the prompt to delete",
                    type: ApplicationCommandOptionType.STRING,
                    required: true
                }
            ],
            execute: makeCommandHandler(async (args, ctx) => {
                const name = findOption(args, "name") as string;
                if (!name) {
                    sendBotMessage(ctx.channel.id, { content: "❌ Please specify a prompt name to delete." });
                    return;
                }

                // Prevent deletion of default prompts
                const defaultPrompts = ["default", "roadman", "egirl"];
                if (defaultPrompts.includes(name)) {
                    sendBotMessage(ctx.channel.id, { content: `❌ Cannot delete built-in prompt "${name}".` });
                    return;
                }

                try {
                    const prompts = await getSystemPrompts();
                    const filteredPrompts = prompts.filter(p => p.name !== name);

                    if (filteredPrompts.length === prompts.length) {
                        sendBotMessage(ctx.channel.id, { content: `❌ No prompt found with name "${name}".` });
                        return;
                    }

                    await saveSystemPrompts(filteredPrompts);

                    // If the deleted prompt was active, reset to default
                    if (settings.store.activePrompt === name) {
                        settings.store.activePrompt = "default";
                        sendBotMessage(ctx.channel.id, { content: `✅ Deleted prompt "${name}" and reset active prompt to "default".` });
                    } else {
                        sendBotMessage(ctx.channel.id, { content: `✅ Deleted prompt "${name}".` });
                    }
                } catch (error) {
                    logger.error("Failed to delete prompt:", error);
                    sendBotMessage(ctx.channel.id, { content: "❌ An error occurred while trying to delete the prompt." });
                }
            })
        },
        {
            name: "ai-list-prompts",
            description: "List all available system prompts",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: makeCommandHandler(async (args, ctx) => {
                try {
                    const prompts = await getSystemPrompts();
                    const { activePrompt } = settings.store;

                    if (prompts.length === 0) {
                        sendBotMessage(ctx.channel.id, { content: "❌ No prompts found." });
                        return;
                    }

                    const promptList = prompts.map(p => {
                        const isActive = p.name === activePrompt ? " ✅ (active)" : "";
                        const preview = p.prompt.length > 100
                            ? p.prompt.substring(0, 100) + "..."
                            : p.prompt;
                        return `• **${p.name}**${isActive}\n  \`${preview}\``;
                    }).join("\n\n");

                    sendBotMessage(ctx.channel.id, {
                        content: `**Available System Prompts:**\n\n${promptList}\n\nUse \`/ai-view-prompt <name>\` to see full content.`
                    });
                } catch (error) {
                    logger.error("Failed to list prompts:", error);
                    sendBotMessage(ctx.channel.id, { content: "❌ An error occurred while trying to list prompts." });
                }
            })
        },
        {
            name: "ai-set-active",
            description: "Set the active system prompt",
            inputType: ApplicationCommandInputType.BUILT_IN,
            options: [
                {
                    name: "name",
                    description: "Name of the prompt to activate",
                    type: ApplicationCommandOptionType.STRING,
                    required: true
                }
            ],
            execute: makeCommandHandler(async (args, ctx) => {
                const name = findOption(args, "name") as string;
                if (!name) {
                    sendBotMessage(ctx.channel.id, { content: "❌ Please specify a prompt name to activate." }); return;
                }

                try {
                    const prompts = await getSystemPrompts();
                    const prompt = prompts.find(p => p.name === name);

                    if (!prompt) {
                        sendBotMessage(ctx.channel.id, { content: `❌ No prompt found with name "${name}". Use /ai-list-prompts to see available prompts.` }); return;
                    }

                    settings.store.activePrompt = name;
                    sendBotMessage(ctx.channel.id, { content: `✅ Activated prompt "${name}".` }); return;
                } catch (error) {
                    logger.error("Failed to set active prompt:", error);
                    sendBotMessage(ctx.channel.id, { content: "❌ An error occurred while trying to set the active prompt." }); return;
                }
            })
        },
        {
            name: "ai-set-context",
            description: "Set persistent context for the current chat",
            inputType: ApplicationCommandInputType.BUILT_IN,
            options: [
                {
                    name: "context",
                    description: "Context information for this chat (leave empty to clear)",
                    type: ApplicationCommandOptionType.STRING,
                    required: false
                }
            ],
            execute: makeCommandHandler(async (args, ctx) => {
                const context = findOption(args, "context", "");
                const channelId = ctx.channel.id;

                try {
                    if (context.trim()) {
                        await setChatContext(channelId, context);
                        sendBotMessage(ctx.channel.id, {
                            content: `✅ Set chat context: "${context.substring(0, 100)}${context.length > 100 ? "..." : ""}"`
                        });
                    } else {
                        await setChatContext(channelId, "");
                        sendBotMessage(ctx.channel.id, {
                            content: "✅ Cleared chat context for this channel."
                        });
                    }
                } catch (error) {
                    logger.error("Failed to set chat context:", error);
                    sendBotMessage(ctx.channel.id, {
                        content: "❌ An error occurred while trying to set the chat context."
                    });
                }
            })
        },
        {
            name: "ai-view-context",
            description: "View the current chat's persistent context",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: makeCommandHandler(async (args, ctx) => {
                const channelId = ctx.channel.id;

                try {
                    const context = await getChatContext(channelId);

                    if (!context) {
                        sendBotMessage(ctx.channel.id, {
                            content: "ℹ️ No persistent context set for this chat. Use `/ai-set-context` to add one."
                        });
                        return;
                    }

                    sendBotMessage(ctx.channel.id, {
                        content: `**Current Chat Context:**\n\`\`\`\n${context}\n\`\`\``
                    });
                } catch (error) {
                    logger.error("Failed to view chat context:", error);
                    sendBotMessage(ctx.channel.id, {
                        content: "❌ An error occurred while trying to view the chat context."
                    });
                }
            })
        },
        {
            name: "ai-toggle-auto",
            description: "Toggle auto-reply for this DM (DMs and Group DMs only).",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: makeCommandHandler(async (_, ctx) => {
                const channel = ChannelStore.getChannel(ctx.channel.id);
                if (!channel) sendBotMessage(ctx.channel.id, { content: "❌ Channel not found" }); return;
                // Only allow in DMs and Group DMs
                if (channel.type !== 1 && channel.type !== 3) {
                    sendBotMessage(ctx.channel.id, { content: "❌ Auto-reply can only be toggled in DMs and Group DMs." }); return;
                }
                const isEnabled = autoReplyChannels.has(ctx.channel.id);
                if (isEnabled) {
                    autoReplyChannels.delete(ctx.channel.id);
                    await saveAutoReplyChannels(autoReplyChannels);
                    sendBotMessage(ctx.channel.id, { content: "❌ Auto-reply disabled for this DM." }); return;
                } else {
                    autoReplyChannels.add(ctx.channel.id);
                    await saveAutoReplyChannels(autoReplyChannels);
                    sendBotMessage(ctx.channel.id, { content: "✅ Auto-reply enabled for this DM. I'll now automatically respond to messages here." }); return;
                }
            })
        }
    ],

    start() {
        document.addEventListener("keydown", handleKeyDown);
        FluxDispatcher.subscribe("MESSAGE_CREATE", handleIncomingMessage);
        getAutoReplyChannels().then(set => { autoReplyChannels = set; });
        logger.info("AiResponder plugin started. Use the chat button, keybind or enable auto-reply for DMs!");
    },

    stop() {
        document.removeEventListener("keydown", handleKeyDown);
        FluxDispatcher.unsubscribe("MESSAGE_CREATE", handleIncomingMessage);

        // Clean up pending replies
        Object.keys(pendingReplies).forEach(channelId => {
            clearTimeout(pendingReplies[channelId]);
            delete pendingReplies[channelId];
        });

        // Clean up pending responses and typing indicators
        Object.keys(pendingResponses).forEach(channelId => {
            const pending = pendingResponses[channelId];
            if (pending.timeoutId) clearTimeout(pending.timeoutId);
            if (pending.typingInterval) clearInterval(pending.typingInterval);
            pending.abortController.abort();
            delete pendingResponses[channelId];
        });

        logger.info("AiResponder plugin stopped.");
    }
});
