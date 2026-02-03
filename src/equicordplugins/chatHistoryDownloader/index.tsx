/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { findGroupChildrenByChildId, NavContextMenuPatchCallback } from "@api/ContextMenu";
import { showNotification } from "@api/Notifications";
import { definePluginSettings } from "@api/Settings";
import { Logger } from "@utils/Logger";
import definePlugin, { OptionType } from "@utils/types";
import { saveFile } from "@utils/web";
import { Message } from "@vencord/discord-types";
import { ChannelStore, Menu, RestAPI, Toasts, UserStore } from "@webpack/common";

const logger = new Logger("ChatHistoryDownloader");

const settings = definePluginSettings({
    defaultMonths: {
        type: OptionType.SLIDER,
        description: "Default months of history to export (0 = all)",
        default: 3,
        markers: [0, 1, 3, 6, 12, 24],
        stickToMarkers: true
    },
});

const activeExports = new Set<string>();

function updateToast(
    id: string,
    message: string,
    type: typeof Toasts.Type[keyof typeof Toasts.Type] = Toasts.Type.MESSAGE,
    duration = 0
) {
    Toasts.show({
        id,
        message,
        type,
        options: {
            duration,
            position: Toasts.Position.BOTTOM
        }
    } as any);
}

function sleep(ms: number) {
    return new Promise<void>(resolve => setTimeout(resolve, ms));
}

function safeFilenamePart(input: string) {
    return (input || "")
        .replace(/[<>:"/\\|?*]/g, "_")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 80);
}

function toUnixMs(timestamp: any): number {
    if (timestamp == null) return 0;

    if (timestamp instanceof Date) return timestamp.getTime();

    if (typeof timestamp === "number") return timestamp;

    if (typeof timestamp === "string") {
        const asNumber = Number(timestamp);
        if (Number.isFinite(asNumber) && asNumber > 0) return asNumber;
        const parsed = Date.parse(timestamp);
        return Number.isFinite(parsed) ? parsed : 0;
    }

    try {
        const str = timestamp.toString?.();
        if (typeof str === "string") {
            const parsed = Date.parse(str);
            return Number.isFinite(parsed) ? parsed : 0;
        }
    } catch {
        // ignore
    }

    return 0;
}

function formatAuthor({ author }: Message) {
    if (!author) return "Unknown";

    const { username } = author;
    const { discriminator } = author as any;

    const base = username ?? "Unknown";
    if (discriminator && discriminator !== "0") return `${base}#${discriminator}`;
    return base;
}

function formatMessage(message: Message) {
    const timestamp = new Date(toUnixMs(message.timestamp)).toLocaleString();
    let content = `[${timestamp}] ${formatAuthor(message)}: ${message.content ?? ""}`;

    if (message.attachments?.length) {
        content += "\n  Attachments:";
        for (const attachment of message.attachments) {
            content += `\n    - ${attachment.filename} (${attachment.url})`;
        }
    }

    if (message.embeds?.length) {
        content += "\n  Embeds:";
        for (const embed of message.embeds) {
            const title = (embed as any).rawTitle ?? (embed as any).title;
            const description = (embed as any).rawDescription ?? (embed as any).description;

            if (title) content += `\n    Title: ${title}`;
            if (description) content += `\n    Description: ${description}`;
            if ((embed as any).url) content += `\n    URL: ${(embed as any).url}`;
        }
    }

    return content;
}

async function downloadText(filename: string, content: string) {
    if (IS_DISCORD_DESKTOP) {
        const data = new TextEncoder().encode(content);
        await DiscordNative.fileManager.saveWithDialog(data, filename);
        return;
    }

    const file = new File([content], filename, { type: "text/plain" });
    saveFile(file);
}

async function fetchChannelHistory(channelId: string, cutoffUnixMs: number | null, toastId: string): Promise<Message[]> {
    const collected: Message[] = [];
    let before: string | undefined;
    let reachedCutoff = false;

    for (let page = 0; page < 10_000; page++) {
        const res = await RestAPI.get({
            url: `/channels/${channelId}/messages`,
            query: {
                limit: 100,
                ...(before ? { before } : {})
            },
            retries: 2
        });

        const messages = (res?.body ?? []) as Message[];
        if (!Array.isArray(messages) || messages.length === 0) break;

        for (const msg of messages) {
            if (cutoffUnixMs != null) {
                const msgTs = toUnixMs(msg.timestamp);
                if (msgTs > 0 && msgTs < cutoffUnixMs) {
                    reachedCutoff = true;
                    break;
                }
            }
            collected.push(msg);
        }

        if (page % 5 === 0) {
            updateToast(toastId, `Downloading chat… fetched ${collected.length} messages so far`);
        }

        if (reachedCutoff) break;

        before = messages[messages.length - 1].id;
        if (!before || messages.length < 100) break;

        // Be gentle even if we aren't rate-limited
        await sleep(150);
    }

    return collected;
}

async function exportChatHistory(channelId: string) {
    if (activeExports.has(channelId)) {
        Toasts.show({
            message: "An export is already running for this channel.",
            type: Toasts.Type.MESSAGE,
            id: Toasts.genId(),
            options: {
                position: Toasts.Position.BOTTOM,
                duration: 3000
            }
        } as any);
        return;
    }

    const channel = ChannelStore.getChannel(channelId) as any;
    if (!channel) return;

    const months = Math.max(0, Math.min(240, Number(settings.store.defaultMonths ?? 3) || 0));
    if (months === 0) {
        const ok = confirm(
            "Exporting the entire chat can take a long time and create a very large file.\n\nContinue?"
        );
        if (!ok) return;
    }

    const cutoffUnixMs = months > 0
        ? Date.now() - months * 30 * 24 * 60 * 60 * 1000
        : null;

    const toastId = Toasts.genId();

    try {
        activeExports.add(channelId);

        updateToast(toastId, "Downloading chat… starting request");

        const messages = await fetchChannelHistory(channelId, cutoffUnixMs, toastId);

        if (!messages.length) {
            updateToast(toastId, "No messages found (or no access).", Toasts.Type.FAILURE, 3000);
            showNotification({
                title: "Chat Export",
                body: "No messages found (or you do not have access).",
                icon: "📄"
            });
            return;
        }

        messages.reverse(); // oldest -> newest

        const now = new Date();
        const channelName = safeFilenamePart(channel.name || channel.rawRecipients?.map((u: any) => u.username).join(", ") || channelId);
        const from = cutoffUnixMs ? new Date(cutoffUnixMs) : null;

        const headerLines: string[] = [];
        headerLines.push("Chat Export");
        headerLines.push(`Channel: ${channelName} (${channelId})`);
        headerLines.push(`Exported by: ${UserStore.getCurrentUser().username}`);
        headerLines.push(`Exported at: ${now.toISOString()}`);
        headerLines.push(`Range: ${from ? `last ~${months} month(s) (since ${from.toISOString()})` : "all available history"}`);
        headerLines.push(`Messages: ${messages.length}`);
        headerLines.push("");

        const body = messages.map(formatMessage).join("\n\n");
        const content = `${headerLines.join("\n")}${body}\n`;

        const datePart = now.toISOString().slice(0, 10);
        const rangePart = months > 0 ? `last-${months}mo` : "all";
        const filename = `chat-${safeFilenamePart(channelName)}-${rangePart}-${datePart}.txt`;

        await downloadText(filename, content);

        updateToast(toastId, `Exported ${messages.length} messages.`, Toasts.Type.SUCCESS, 3000);

        showNotification({
            title: "Chat Export",
            body: `Exported ${messages.length} messages to ${filename}`,
            icon: "✅"
        });
    } catch (err) {
        updateToast(toastId, "Failed to export chat history.", Toasts.Type.FAILURE, 5000);
        logger.error("Failed to export chat history", err);

        showNotification({
            title: "Chat Export",
            body: "Failed to export chat history. Try a smaller range.",
            icon: "❌"
        });
    } finally {
        activeExports.delete(channelId);
    }
}

const ChannelContextMenuPatch: NavContextMenuPatchCallback = (children, args) => {
    const channel = args?.channel ?? ChannelStore.getChannel(args?.channelId);
    if (!channel?.id) return;

    const group = findGroupChildrenByChildId(["mark-channel-read", "mark-guild-read"], children, true) ?? children;

    group.push(
        <Menu.MenuItem
            id="vc-chat-export"
            label="Download chat as .txt"
            action={() => exportChatHistory(channel.id)}
        />
    );
};

const MessageContextMenuPatch: NavContextMenuPatchCallback = (children, { message }: { message?: Message; }) => {
    const channelId = message?.channel_id;
    if (!channelId) return;

    children.push(
        <Menu.MenuItem
            id="vc-chat-export-from-message"
            label="Download this chat as .txt"
            action={() => exportChatHistory(channelId)}
        />
    );
};

export default definePlugin({
    name: "ChatHistoryDownloader",
    description: "Download the current chat history as a .txt file from the channel context menu",
    authors: [{ name: "Sufo", id: 1234567890n }],
    settings,
    contextMenus: {
        "message": MessageContextMenuPatch,
        // These cover server channels, threads, and DMs/GDMs depending on where you right-click
        "channel-context": ChannelContextMenuPatch,
        "thread-context": ChannelContextMenuPatch,
        "user-context": ChannelContextMenuPatch,
        "gdm-context": ChannelContextMenuPatch,
    }
});
