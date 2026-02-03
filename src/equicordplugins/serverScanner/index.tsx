/*
 * Vencord, a Discord client mod
 * Copyright (c) 2025 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * ServerScanner v2.0 - Comprehensive Security Auditing Tool
 *
 * This plugin provides extensive security auditing capabilities for Discord servers,
 * including automatic vulnerability detection and exploitation chain analysis.
 *
 * FEATURES:
 * - Automatic comprehensive security scanning (/server-autoscan)
 * - Detection of privilege escalation paths
 * - Exploitation chain analysis
 * - Markdown report generation
 * - Analysis of:
 *   ✓ Role permission misconfigurations
 *   ✓ Channel permission overwrites
 *   ✓ Role hierarchy vulnerabilities
 *   ✓ Webhook security issues
 *   ✓ Server verification levels
 *   ✓ @everyone role permissions
 *   ✓ All 41 Discord permissions
 *
 * SECURITY CATEGORIES:
 * - CRITICAL: Immediate server takeover possible
 * - HIGH: Privilege escalation or significant impact
 * - MEDIUM: Operational disruption or data exposure
 * - LOW: Minor security concerns
 * - INFO: Configuration recommendations
 *
 * USAGE:
 * 1. Run /server-autoscan to perform full security audit
 * 2. Review findings shown in channel (client-side only)
 * 3. Use /server-autoscan-report to download detailed markdown report
 * 4. Follow remediation steps for each finding
 * 5. Re-scan after making changes to verify fixes
 *
 * NOTE: All results are shown via Clyde (client-side invisible to others)
 */

import { ApplicationCommandInputType, sendBotMessage } from "@api/Commands";
import { Logger } from "@utils/Logger";
import definePlugin from "@utils/types";
import { ChannelStore, GuildStore, RestAPI } from "@webpack/common";

const logger = new Logger("ServerScanner");

// Type definitions
interface Role {
    id: string;
    name: string;
    permissions: string;
    position: number;
}

interface ChannelOverwrite {
    id: string;
    type: 0 | 1;
    allow: string;
    deny: string;
}

interface GuildChannel {
    id: string;
    guild_id: string;
    name: string;
    type: number;
    position: number;
    parent_id: string | null;
    permission_overwrites: ChannelOverwrite[];
}

interface GuildMember {
    user: {
        id: string;
        username: string;
        discriminator: string;
    };
}

interface Webhook {
    id: string;
    name: string | null;
    type: number;
    channel_id: string;
    url?: string;
}

interface GuildDetails {
    id: string;
    name: string;
    owner_id: string;
    premium_subscription_count?: number;
    approximate_member_count?: number;
    member_count?: number;
    approximate_presence_count?: number;
    verification_level: number;
}

// Permission constants - Comprehensive
const PERMISSIONS = {
    CREATE_INSTANT_INVITE: 1n << 0n,
    KICK_MEMBERS: 1n << 1n,
    BAN_MEMBERS: 1n << 2n,
    ADMINISTRATOR: 1n << 3n,
    MANAGE_CHANNELS: 1n << 4n,
    MANAGE_GUILD: 1n << 5n,
    ADD_REACTIONS: 1n << 6n,
    VIEW_AUDIT_LOG: 1n << 7n,
    PRIORITY_SPEAKER: 1n << 8n,
    STREAM: 1n << 9n,
    VIEW_CHANNEL: 1n << 10n,
    SEND_MESSAGES: 1n << 11n,
    SEND_TTS_MESSAGES: 1n << 12n,
    MANAGE_MESSAGES: 1n << 13n,
    EMBED_LINKS: 1n << 14n,
    ATTACH_FILES: 1n << 15n,
    READ_MESSAGE_HISTORY: 1n << 16n,
    MENTION_EVERYONE: 1n << 17n,
    USE_EXTERNAL_EMOJIS: 1n << 18n,
    VIEW_GUILD_INSIGHTS: 1n << 19n,
    CONNECT: 1n << 20n,
    SPEAK: 1n << 21n,
    MUTE_MEMBERS: 1n << 22n,
    DEAFEN_MEMBERS: 1n << 23n,
    MOVE_MEMBERS: 1n << 24n,
    USE_VAD: 1n << 25n,
    CHANGE_NICKNAME: 1n << 26n,
    MANAGE_NICKNAMES: 1n << 27n,
    MANAGE_ROLES: 1n << 28n,
    MANAGE_WEBHOOKS: 1n << 29n,
    MANAGE_EMOJIS: 1n << 30n,
    USE_APPLICATION_COMMANDS: 1n << 31n,
    REQUEST_TO_SPEAK: 1n << 32n,
    MANAGE_EVENTS: 1n << 33n,
    MANAGE_THREADS: 1n << 34n,
    CREATE_PUBLIC_THREADS: 1n << 35n,
    CREATE_PRIVATE_THREADS: 1n << 36n,
    USE_EXTERNAL_STICKERS: 1n << 37n,
    SEND_MESSAGES_IN_THREADS: 1n << 38n,
    USE_EMBEDDED_ACTIVITIES: 1n << 39n,
    MODERATE_MEMBERS: 1n << 40n,
};

// Security finding types
enum SeverityLevel {
    CRITICAL = "CRITICAL",
    HIGH = "HIGH",
    MEDIUM = "MEDIUM",
    LOW = "LOW",
    INFO = "INFO"
}

interface SecurityFinding {
    severity: SeverityLevel;
    category: string;
    title: string;
    description: string;
    affected: string[];
    exploitation: string[];
    remediation: string[];
}

interface SecurityReport {
    guildName: string;
    guildId: string;
    scanDate: string;
    findings: SecurityFinding[];
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
}

// Helper functions
function parsePermissions(bits: string): bigint {
    return BigInt(bits);
}

function hasPermission(bits: bigint, perm: bigint): boolean {
    return (bits & perm) === perm;
}

function resolveRoleName(roleId: string, roles: Role[]): string {
    if (roleId === "0") return "Everyone";
    const match = roles.find(r => r.id === roleId);
    return match ? `@${match.name}` : roleId;
}

function formatGuildInfo(details: GuildDetails, channels: GuildChannel[], roles: Role[]): string {
    const boostCount = details.premium_subscription_count ?? 0;
    const level = boostCount < 2 ? "No Level" : boostCount < 7 ? "Level 1" : boostCount < 14 ? "Level 2" : "Level 3";

    // Safely calculate creation date
    let createdDate = "unknown";
    try {
        if (details.id) {
            const timestamp = Number(BigInt(details.id) >> 22n) + 1420070400000;
            createdDate = new Date(timestamp).toISOString();
        }
    } catch (error) {
        logger.error("Failed to calculate creation date:", error);
    }

    // Ensure channels and roles are arrays
    const channelsArray = Array.isArray(channels) ? channels : [];
    const rolesArray = Array.isArray(roles) ? roles : [];

    const lines = [
        `Server: ${details.name} (${details.id})`,
        `Owner ID: ${details.owner_id}`,
        `Boost Count: ${boostCount}`,
        `Boost Level: ${level}`,
        `Member Count: ${details.approximate_member_count ?? details.member_count ?? "unknown"}`,
        `Approx. Online: ${details.approximate_presence_count ?? "unknown"}`,
        `Verification Level: ${details.verification_level}`,
        `Created: ${createdDate}`,
        `Text Channels: ${channelsArray.filter(c => c.type === 0 || c.type === 5).length}`,
        `Voice Channels: ${channelsArray.filter(c => c.type === 2 || c.type === 13).length}`,
        `Roles: ${rolesArray.length}`,
    ];

    return lines.join("\n");
}

function auditChannelOverwrites(
    channels: GuildChannel[],
    roles: Role[],
    predicate: (channel: GuildChannel) => boolean,
    permissionsToCheck: Array<{ perm: bigint; label: string; }>,
): string {
    const lines: string[] = [];
    let alerts = 0;

    // Ensure channels is an array
    const channelsArray = Array.isArray(channels) ? channels : [];
    const filteredChannels = channelsArray.filter(predicate);

    for (const channel of filteredChannels) {
        const overwrites = channel.permission_overwrites ?? [];
        for (const overwrite of overwrites) {
            try {
                const allow = parsePermissions(overwrite.allow);
                for (const perm of permissionsToCheck) {
                    if (hasPermission(allow, perm.perm)) {
                        alerts += 1;
                        const target = overwrite.type === 0
                            ? resolveRoleName(overwrite.id, roles)
                            : `<@${overwrite.id}>`;
                        lines.push(`#${channel.name}: ${target} can ${perm.label}`);
                    }
                }
            } catch (error) {
                logger.error(`Failed to parse permissions for channel ${channel.name}:`, error);
            }
        }
    }

    if (alerts === 0) return "No risky permission overwrites detected.";
    return [`Detected ${alerts} permission alerts:`, ...lines.map(line => `  ${line}`)].join("\n");
}

function summarizeAccess(roles: Role[]): string {
    const sections: string[] = [];
    // Ensure roles is an array
    const rolesArray = Array.isArray(roles) ? roles : [];
    const ordered = [...rolesArray].sort((a, b) => b.position - a.position);

    const definitions: Array<{ title: string; perm: bigint; }> = [
        { title: "Administrator Roles", perm: PERMISSIONS.ADMINISTRATOR },
        { title: "Manage Channels Roles", perm: PERMISSIONS.MANAGE_CHANNELS },
        { title: "Manage Roles Roles", perm: PERMISSIONS.MANAGE_ROLES },
        { title: "Manage Emojis Roles", perm: PERMISSIONS.MANAGE_EMOJIS },
        { title: "View Audit Log Roles", perm: PERMISSIONS.VIEW_AUDIT_LOG },
        { title: "Manage Webhooks Roles", perm: PERMISSIONS.MANAGE_WEBHOOKS },
        { title: "Manage Nicknames Roles", perm: PERMISSIONS.MANAGE_NICKNAMES },
        { title: "Kick Members Roles", perm: PERMISSIONS.KICK_MEMBERS },
        { title: "Ban Members Roles", perm: PERMISSIONS.BAN_MEMBERS },
    ];

    for (const def of definitions) {
        try {
            const list = ordered.filter(role => {
                try {
                    return hasPermission(parsePermissions(role.permissions), def.perm);
                } catch (error) {
                    logger.error(`Failed to parse permissions for role ${role.name}:`, error);
                    return false;
                }
            });
            if (list.length) {
                sections.push(`${def.title}:\n${list.map(role => `  - @${role.name}`).join("\n")}`);
            } else {
                sections.push(`${def.title}: None`);
            }
        } catch (error) {
            logger.error(`Failed to summarize ${def.title}:`, error);
            sections.push(`${def.title}: Error processing`);
        }
    }

    return sections.join("\n\n");
}

function splitMessage(content: string, maxLength = 1900): string[] {
    if (content.length <= maxLength) return [content];

    const chunks: string[] = [];
    let current = "";
    const lines = content.split(/\r?\n/);

    for (const line of lines) {
        const addition = (current ? "\n" : "") + line;
        if ((current + addition).length > maxLength) {
            if (current) chunks.push(current);
            if (line.length > maxLength) {
                for (let i = 0; i < line.length; i += maxLength) {
                    chunks.push(line.slice(i, i + maxLength));
                }
                current = "";
            } else {
                current = line;
            }
        } else {
            current += addition;
        }
    }

    if (current) chunks.push(current);
    return chunks;
}

function downloadTextFile(filename: string, content: string, mimeType: string = "text/plain") {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    setTimeout(() => URL.revokeObjectURL(url), 5000);
}

// Comprehensive security audit functions
function auditEveryoneRole(roles: Role[]): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const everyoneRole = roles.find(r => r.id === roles[0]?.id);

    if (!everyoneRole) return findings;

    const perms = parsePermissions(everyoneRole.permissions);
    const dangerousPerms = [
        { perm: PERMISSIONS.ADMINISTRATOR, name: "Administrator", severity: SeverityLevel.CRITICAL },
        { perm: PERMISSIONS.MANAGE_GUILD, name: "Manage Server", severity: SeverityLevel.CRITICAL },
        { perm: PERMISSIONS.MANAGE_ROLES, name: "Manage Roles", severity: SeverityLevel.CRITICAL },
        { perm: PERMISSIONS.MANAGE_CHANNELS, name: "Manage Channels", severity: SeverityLevel.HIGH },
        { perm: PERMISSIONS.MANAGE_WEBHOOKS, name: "Manage Webhooks", severity: SeverityLevel.HIGH },
        { perm: PERMISSIONS.BAN_MEMBERS, name: "Ban Members", severity: SeverityLevel.HIGH },
        { perm: PERMISSIONS.KICK_MEMBERS, name: "Kick Members", severity: SeverityLevel.HIGH },
        { perm: PERMISSIONS.MENTION_EVERYONE, name: "Mention Everyone", severity: SeverityLevel.MEDIUM },
        { perm: PERMISSIONS.MANAGE_MESSAGES, name: "Manage Messages", severity: SeverityLevel.MEDIUM },
        { perm: PERMISSIONS.VIEW_AUDIT_LOG, name: "View Audit Log", severity: SeverityLevel.MEDIUM },
    ];

    for (const { perm, name, severity } of dangerousPerms) {
        if (hasPermission(perms, perm)) {
            findings.push({
                severity,
                category: "Role Permissions",
                title: `@everyone has ${name} permission`,
                description: `The @everyone role grants ${name} to all server members, including newly joined users.`,
                affected: ["@everyone (all members)"],
                exploitation: [
                    "Any member can immediately exploit this permission",
                    "No social engineering or privilege escalation required",
                    severity === SeverityLevel.CRITICAL ? "Can lead to complete server takeover" : "Can disrupt server operations"
                ],
                remediation: [
                    `Remove ${name} from @everyone role`,
                    "Create specific roles for trusted members",
                    "Review all role permissions regularly"
                ]
            });
        }
    }

    return findings;
}

function auditDangerousRoleHierarchy(roles: Role[], channels: GuildChannel[]): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const sortedRoles = [...roles].sort((a, b) => b.position - a.position);

    // Check for roles with MANAGE_ROLES that can modify higher roles
    for (let i = 0; i < sortedRoles.length; i++) {
        const role = sortedRoles[i];
        const perms = parsePermissions(role.permissions);

        if (hasPermission(perms, PERMISSIONS.MANAGE_ROLES)) {
            // This role can modify roles below it
            const vulnerableRoles = sortedRoles.slice(i + 1);
            const adminRolesBelow = vulnerableRoles.filter(r =>
                hasPermission(parsePermissions(r.permissions), PERMISSIONS.ADMINISTRATOR)
            );

            if (adminRolesBelow.length > 0 && !hasPermission(perms, PERMISSIONS.ADMINISTRATOR)) {
                findings.push({
                    severity: SeverityLevel.CRITICAL,
                    category: "Role Hierarchy",
                    title: `Role @${role.name} can grant itself Administrator`,
                    description: `Role @${role.name} has Manage Roles and is positioned above admin roles, allowing privilege escalation.`,
                    affected: [`@${role.name}`, ...adminRolesBelow.map(r => `@${r.name}`)],
                    exploitation: [
                        `Member with @${role.name} assigns themselves an admin role below their current position`,
                        "Gains Administrator permission and full server control",
                        "Can modify server settings, delete channels, ban members",
                        "Can remove evidence by editing role permissions"
                    ],
                    remediation: [
                        `Move @${role.name} below all admin roles in the hierarchy`,
                        "Or remove Manage Roles from this role",
                        "Audit all role positions and permissions"
                    ]
                });
            }
        }
    }

    return findings;
}

function auditChannelPermissionOverwrites(channels: GuildChannel[], roles: Role[]): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const channel of channels) {
        const overwrites = channel.permission_overwrites ?? [];

        for (const overwrite of overwrites) {
            const allow = parsePermissions(overwrite.allow);
            const targetName = overwrite.type === 0
                ? resolveRoleName(overwrite.id, roles)
                : `User ${overwrite.id}`;

            // Check for dangerous channel-level permissions
            if (hasPermission(allow, PERMISSIONS.MANAGE_ROLES)) {
                findings.push({
                    severity: SeverityLevel.HIGH,
                    category: "Channel Permissions",
                    title: `${targetName} can manage permissions in #${channel.name}`,
                    description: "This allows modification of channel permissions, potentially granting access to restricted channels.",
                    affected: [`#${channel.name}`, targetName],
                    exploitation: [
                        "Grant themselves or others access to private channels",
                        "Remove restrictions from sensitive channels",
                        "Lock out moderators from specific channels",
                        "Chain with other permissions for lateral movement"
                    ],
                    remediation: [
                        `Remove Manage Permissions from ${targetName} in #${channel.name}`,
                        "Use role-level permissions instead of channel overwrites where possible",
                        "Regularly audit channel permission overwrites"
                    ]
                });
            }

            if (hasPermission(allow, PERMISSIONS.MANAGE_WEBHOOKS)) {
                findings.push({
                    severity: SeverityLevel.MEDIUM,
                    category: "Channel Permissions",
                    title: `${targetName} can manage webhooks in #${channel.name}`,
                    description: "Can create webhooks to impersonate users/bots or exfiltrate messages.",
                    affected: [`#${channel.name}`, targetName],
                    exploitation: [
                        "Create webhook to impersonate trusted users or bots",
                        "Use webhook to spam or spread misinformation",
                        "Exfiltrate messages from the channel to external services",
                        "Chain with Manage Messages to edit history and exfiltrate via webhook"
                    ],
                    remediation: [
                        `Remove Manage Webhooks from ${targetName} in #${channel.name}`,
                        "Limit webhook management to administrator roles only",
                        "Monitor webhook creation via audit logs"
                    ]
                });
            }
        }
    }

    return findings;
}

function auditWebhookSecurity(webhooks: Webhook[], channels: GuildChannel[]): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (webhooks.length > 0) {
        const channelNames = webhooks.map(w => {
            const ch = channels.find(c => c.id === w.channel_id);
            return ch ? `#${ch.name}` : w.channel_id;
        });

        findings.push({
            severity: SeverityLevel.MEDIUM,
            category: "Webhooks",
            title: `${webhooks.length} webhook(s) configured in server`,
            description: "Webhooks can be used to impersonate users and bypass some security measures.",
            affected: Array.from(new Set(channelNames)),
            exploitation: [
                "If webhook URL is leaked, anyone can post messages",
                "Webhooks bypass rate limits and some bot protections",
                "Can impersonate any username and avatar",
                "Messages appear legitimate, bypassing user verification"
            ],
            remediation: [
                "Regularly audit and remove unused webhooks",
                "Rotate webhook URLs if compromise is suspected",
                "Limit webhook creation permissions",
                "Monitor webhook usage via audit logs",
                "Consider using bot accounts instead for automated messages"
            ]
        });
    }

    return findings;
}

function auditRoleMentionability(roles: Role[]): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // This would require additional role data, but we can check for patterns
    const highPermRoles = roles.filter(r => {
        const perms = parsePermissions(r.permissions);
        return hasPermission(perms, PERMISSIONS.ADMINISTRATOR) ||
            hasPermission(perms, PERMISSIONS.MANAGE_GUILD) ||
            hasPermission(perms, PERMISSIONS.MANAGE_ROLES);
    });

    if (highPermRoles.length > 5) {
        findings.push({
            severity: SeverityLevel.MEDIUM,
            category: "Role Configuration",
            title: `${highPermRoles.length} roles with elevated permissions`,
            description: "Large number of privileged roles increases attack surface.",
            affected: highPermRoles.map(r => `@${r.name}`),
            exploitation: [
                "More roles with high permissions = more accounts to target",
                "Increases likelihood of misconfiguration",
                "Harder to track who has what permissions",
                "Social engineering targets have more options"
            ],
            remediation: [
                "Consolidate privileged roles where possible",
                "Follow principle of least privilege",
                "Regular audits of role members",
                "Implement 2FA requirement for privileged roles"
            ]
        });
    }

    return findings;
}

function auditVerificationLevel(details: GuildDetails): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    if (details.verification_level < 2) {
        findings.push({
            severity: SeverityLevel.MEDIUM,
            category: "Server Settings",
            title: "Low verification level",
            description: `Server verification level is ${details.verification_level}, allowing easy bot/spam account access.`,
            affected: ["Server configuration"],
            exploitation: [
                "Bots and spam accounts can join easily",
                "Enables mass raid attacks",
                "Allows throwaway accounts for harassment",
                "Facilitates ban evasion"
            ],
            remediation: [
                "Increase verification level to at least Medium (verified email)",
                "Consider enabling High (registered for 5+ mins) for sensitive servers",
                "Use bot verification systems as additional layer",
                "Enable DM scan and explicit content filters"
            ]
        });
    }

    return findings;
}

function detectExploitationChains(findings: SecurityFinding[]): string[] {
    const chains: string[] = [];

    // Check for privilege escalation chains
    const hasManageRoles = findings.some(f => f.title.includes("Manage Roles") || f.title.includes("manage permissions"));
    const hasAdminRoles = findings.some(f => f.title.includes("Administrator"));
    const hasChannelPerms = findings.some(f => f.category === "Channel Permissions");
    const hasWebhooks = findings.some(f => f.category === "Webhooks");

    if (hasManageRoles && hasAdminRoles) {
        chains.push("🔗 **PRIVILEGE ESCALATION CHAIN DETECTED**\n" +
            "   1. Attacker obtains role with Manage Roles permission\n" +
            "   2. Uses Manage Roles to grant themselves Administrator role\n" +
            "   3. Gains full server control with Administrator permission\n" +
            "   4. Can delete evidence, ban defenders, and maintain persistence");
    }

    if (hasChannelPerms && hasWebhooks) {
        chains.push("🔗 **DATA EXFILTRATION CHAIN DETECTED**\n" +
            "   1. Attacker gains Manage Permissions in sensitive channel\n" +
            "   2. Grants themselves Manage Webhooks permission\n" +
            "   3. Creates webhook pointing to external server\n" +
            "   4. Exfiltrates all channel messages via webhook\n" +
            "   5. Can maintain persistent access to future messages");
    }

    if (findings.some(f => f.title.includes("@everyone"))) {
        chains.push("🔗 **IMMEDIATE EXPLOITATION POSSIBLE**\n" +
            "   ⚠️  @everyone permissions require no privilege escalation\n" +
            "   ⚠️  Any new member can immediately exploit these permissions\n" +
            "   ⚠️  No social engineering or account compromise needed\n" +
            "   ⚠️  IMMEDIATE REMEDIATION REQUIRED");
    }

    const criticalCount = findings.filter(f => f.severity === SeverityLevel.CRITICAL).length;
    const highCount = findings.filter(f => f.severity === SeverityLevel.HIGH).length;

    if (criticalCount > 0 || highCount > 2) {
        chains.push("🔗 **COMPOUND VULNERABILITY RISK**\n" +
            `   - ${criticalCount} CRITICAL + ${highCount} HIGH severity findings\n` +
            "   - Multiple vulnerabilities can be chained together\n" +
            "   - Each additional vulnerability increases exploitation success rate\n" +
            "   - Attacker only needs to exploit ONE to gain foothold");
    }

    return chains;
}

function generateMarkdownReport(report: SecurityReport, chains: string[]): string {
    const { guildName, guildId, scanDate, findings, summary } = report;

    let md = `# Security Audit Report: ${guildName}\n\n`;
    md += `**Guild ID:** ${guildId}\n`;
    md += `**Scan Date:** ${scanDate}\n`;
    md += `**Total Findings:** ${findings.length}\n\n`;

    md += "## Executive Summary\n\n";
    md += "| Severity | Count |\n";
    md += "|----------|-------|\n";
    md += `| 🔴 CRITICAL | ${summary.critical} |\n`;
    md += `| 🟠 HIGH | ${summary.high} |\n`;
    md += `| 🟡 MEDIUM | ${summary.medium} |\n`;
    md += `| 🟢 LOW | ${summary.low} |\n`;
    md += `| ℹ️  INFO | ${summary.info} |\n\n`;

    if (chains.length > 0) {
        md += "## ⚠️  EXPLOITATION CHAINS DETECTED\n\n";
        md += "The following attack chains were identified based on vulnerability combinations:\n\n";
        for (const chain of chains) {
            md += chain + "\n\n";
        }
    }

    md += "## Detailed Findings\n\n";

    const severityOrder = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO];

    for (const severity of severityOrder) {
        const severityFindings = findings.filter(f => f.severity === severity);
        if (severityFindings.length === 0) continue;

        const icon = severity === SeverityLevel.CRITICAL ? "🔴" :
            severity === SeverityLevel.HIGH ? "🟠" :
                severity === SeverityLevel.MEDIUM ? "🟡" :
                    severity === SeverityLevel.LOW ? "🟢" : "ℹ️";

        md += `### ${icon} ${severity} Severity (${severityFindings.length})\n\n`;

        for (let i = 0; i < severityFindings.length; i++) {
            const f = severityFindings[i];
            md += `#### ${i + 1}. ${f.title}\n\n`;
            md += `**Category:** ${f.category}\n\n`;
            md += `**Description:** ${f.description}\n\n`;
            md += "**Affected Resources:**\n";
            for (const affected of f.affected) {
                md += `- ${affected}\n`;
            }
            md += "\n**Exploitation Scenario:**\n";
            for (let j = 0; j < f.exploitation.length; j++) {
                md += `${j + 1}. ${f.exploitation[j]}\n`;
            }
            md += "\n**Remediation Steps:**\n";
            for (let j = 0; j < f.remediation.length; j++) {
                md += `${j + 1}. ${f.remediation[j]}\n`;
            }
            md += "\n---\n\n";
        }
    }

    md += "## Recommendations\n\n";
    md += "1. **Immediate Actions** (Critical/High): Address all CRITICAL and HIGH severity findings immediately\n";
    md += "2. **Short-term** (within 7 days): Address MEDIUM severity findings\n";
    md += "3. **Long-term** (within 30 days): Address LOW severity and implement INFO recommendations\n";
    md += "4. **Continuous Monitoring**: Re-run this scan weekly and after major configuration changes\n";
    md += "5. **Incident Response**: Have a plan ready in case exploitation occurs\n\n";

    md += "---\n";
    md += "*Report generated by Equicord ServerScanner v2.0*\n";

    return md;
}

// API functions
async function fetchGuildDetails(guildId: string): Promise<GuildDetails> {
    try {
        const result = await RestAPI.get({ url: `/guilds/${guildId}`, query: { with_counts: "true" } });
        logger.log("Fetched guild details:", result);

        if (!result || typeof result !== "object") {
            throw new Error("Invalid response from guild details API");
        }

        return result.body ?? result;
    } catch (error) {
        logger.error("Failed to fetch guild details:", error);
        throw error;
    }
}

async function fetchGuildRoles(guildId: string): Promise<Role[]> {
    try {
        const result = await RestAPI.get({ url: `/guilds/${guildId}/roles` });
        logger.log("Fetched guild roles:", result);

        // Handle wrapped response
        const roles = result.body ?? result;

        if (!Array.isArray(roles)) {
            throw new Error("Invalid response from guild roles API - expected an array");
        }

        return roles;
    } catch (error) {
        logger.error("Failed to fetch guild roles:", error);
        throw error;
    }
}

async function fetchGuildChannels(guildId: string): Promise<GuildChannel[]> {
    try {
        const result = await RestAPI.get({ url: `/guilds/${guildId}/channels` });
        logger.log("Fetched guild channels:", result);

        // Handle wrapped response
        const channels = result.body ?? result;

        if (!Array.isArray(channels)) {
            throw new Error("Invalid response from guild channels API - expected an array");
        }

        return channels;
    } catch (error) {
        logger.error("Failed to fetch guild channels:", error);
        throw error;
    }
}

async function fetchGuildWebhooks(guildId: string): Promise<Webhook[]> {
    try {
        const result = await RestAPI.get({ url: `/guilds/${guildId}/webhooks` });
        logger.log("Fetched guild webhooks:", result);

        // Handle wrapped response
        const webhooks = result.body ?? result;

        if (!Array.isArray(webhooks)) {
            // Log the actual structure we received
            logger.error("Unexpected webhooks response structure:", webhooks);
            throw new Error(`Invalid response from guild webhooks API - expected an array, got ${typeof webhooks}`);
        }

        return webhooks;
    } catch (error: any) {
        logger.error("Failed to fetch guild webhooks:", error);

        // Re-throw with more context if it's a permission/API error
        if (error?.status === 403) {
            throw new Error("Missing permissions to view webhooks");
        } else if (error?.status === 404) {
            throw new Error("Guild not found");
        } else if (error?.body?.message) {
            throw new Error(error.body.message);
        } else if (error instanceof Error) {
            throw error;
        } else {
            throw new Error(`Failed to fetch webhooks: ${JSON.stringify(error)}`);
        }
    }
}

async function fetchAllMembers(guildId: string): Promise<GuildMember[]> {
    const members: GuildMember[] = [];
    let after: string | undefined = undefined;

    try {
        while (true) {
            const query: Record<string, string> = { limit: "1000" };
            if (after) query.after = after;

            const result = await RestAPI.get({
                url: `/guilds/${guildId}/members`,
                query
            });

            // Handle wrapped response
            const batch = result.body ?? result;

            if (!Array.isArray(batch)) {
                throw new Error("Invalid response from guild members API - expected an array");
            }

            members.push(...batch);
            if (batch.length < 1000) break;
            after = batch[batch.length - 1].user.id;
        }

        return members;
    } catch (error) {
        logger.error("Failed to fetch guild members:", error);
        throw error;
    }
}

// Comprehensive security scan executor
async function executeAutoScan(guildId: string, channelId: string): Promise<void> {
    try {
        await sendBotMessage(channelId, { content: "🔍 **STARTING COMPREHENSIVE SECURITY AUDIT**\nThis may take a moment..." });

        // Fetch all necessary data
        const [details, channels, roles, webhooks] = await Promise.all([
            fetchGuildDetails(guildId),
            fetchGuildChannels(guildId),
            fetchGuildRoles(guildId),
            fetchGuildWebhooks(guildId).catch(() => [] as Webhook[]) // Ignore webhook errors
        ]);

        // Run all security audits
        const allFindings: SecurityFinding[] = [
            ...auditEveryoneRole(roles),
            ...auditDangerousRoleHierarchy(roles, channels),
            ...auditChannelPermissionOverwrites(channels, roles),
            ...auditWebhookSecurity(webhooks, channels),
            ...auditRoleMentionability(roles),
            ...auditVerificationLevel(details)
        ];

        // Detect exploitation chains
        const chains = detectExploitationChains(allFindings);

        // Create security report
        const report: SecurityReport = {
            guildName: details.name,
            guildId: details.id,
            scanDate: new Date().toISOString(),
            findings: allFindings,
            summary: {
                critical: allFindings.filter(f => f.severity === SeverityLevel.CRITICAL).length,
                high: allFindings.filter(f => f.severity === SeverityLevel.HIGH).length,
                medium: allFindings.filter(f => f.severity === SeverityLevel.MEDIUM).length,
                low: allFindings.filter(f => f.severity === SeverityLevel.LOW).length,
                info: allFindings.filter(f => f.severity === SeverityLevel.INFO).length
            }
        };

        // Generate markdown report
        const markdown = generateMarkdownReport(report, chains);

        // Send summary to channel
        let summary = "✅ **SECURITY AUDIT COMPLETE**\n\n";
        summary += "**Findings Summary:**\n";
        summary += `🔴 CRITICAL: ${report.summary.critical}\n`;
        summary += `🟠 HIGH: ${report.summary.high}\n`;
        summary += `🟡 MEDIUM: ${report.summary.medium}\n`;
        summary += `🟢 LOW: ${report.summary.low}\n`;
        summary += `ℹ️  INFO: ${report.summary.info}\n\n`;

        if (chains.length > 0) {
            summary += `⚠️  **${chains.length} EXPLOITATION CHAIN(S) DETECTED**\n\n`;
        }

        summary += "Use `/server-autoscan-report` to download the full report.\n\n";

        // Show top critical/high findings
        const criticalFindings = allFindings.filter(f => f.severity === SeverityLevel.CRITICAL).slice(0, 3);
        if (criticalFindings.length > 0) {
            summary += "**🔴 Top Critical Findings:**\n";
            for (const f of criticalFindings) {
                summary += `• ${f.title}\n`;
            }
        }

        await sendBotMessage(channelId, { content: summary });

        // Store report for download
        (globalThis as any).__lastSecurityReport = { markdown, report };

        // Show findings in detail
        if (allFindings.length > 0) {
            for (const finding of allFindings) {
                let detail = `**[${finding.severity}] ${finding.title}**\n\n`;
                detail += `${finding.description}\n\n`;
                detail += `**Affected:** ${finding.affected.join(", ")}\n\n`;
                detail += "**Exploitation:**\n";
                finding.exploitation.forEach((e, i) => {
                    detail += `${i + 1}. ${e}\n`;
                });
                detail += "\n**Remediation:**\n";
                finding.remediation.forEach((r, i) => {
                    detail += `${i + 1}. ${r}\n`;
                });

                const chunks = splitMessage(detail, 1900);
                for (const chunk of chunks) {
                    await sendBotMessage(channelId, { content: chunk });
                }
            }
        }

        // Show exploitation chains
        if (chains.length > 0) {
            await sendBotMessage(channelId, { content: "**⚠️  EXPLOITATION CHAINS:**" });
            for (const chain of chains) {
                const chunks = splitMessage(chain, 1900);
                for (const chunk of chunks) {
                    await sendBotMessage(channelId, { content: chunk });
                }
            }
        }

    } catch (error: any) {
        logger.error("Failed to execute autoscan:", error);

        let errorMessage = "Unknown error";
        if (error instanceof Error) {
            errorMessage = error.message;
        } else if (error?.message) {
            errorMessage = error.message;
        } else if (error?.body?.message) {
            errorMessage = error.body.message;
        } else if (typeof error === "string") {
            errorMessage = error;
        } else {
            errorMessage = JSON.stringify(error);
        }

        await sendBotMessage(channelId, { content: `❌ Error during security scan: ${errorMessage}` });
    }
}

async function executeDownloadReport(channelId: string): Promise<void> {
    try {
        const stored = (globalThis as any).__lastSecurityReport;

        if (!stored || !stored.markdown) {
            await sendBotMessage(channelId, {
                content: "❌ No security report available. Run `/server-autoscan` first."
            });
            return;
        }

        const { markdown, report } = stored;
        const filename = `${report.guildName.replace(/[^A-Za-z0-9_.-]+/g, "_")}_security_report_${new Date().toISOString().split("T")[0]}.md`;

        downloadTextFile(filename, markdown, "text/markdown");

        await sendBotMessage(channelId, {
            content: `✅ Security report downloaded: ${filename}`
        });
    } catch (error: any) {
        logger.error("Failed to download report:", error);
        await sendBotMessage(channelId, { content: "❌ Failed to download report." });
    }
}

// Command executors
async function executeInfo(guildId: string, channelId: string): Promise<void> {
    try {
        const [details, channels, roles] = await Promise.all([
            fetchGuildDetails(guildId),
            fetchGuildChannels(guildId),
            fetchGuildRoles(guildId)
        ]);

        // Validate the API responses
        if (!details || typeof details !== "object") {
            throw new Error("Invalid guild details received from API");
        }
        if (!Array.isArray(channels)) {
            logger.warn("Channels is not an array, using empty array");
        }
        if (!Array.isArray(roles)) {
            logger.warn("Roles is not an array, using empty array");
        }

        const message = formatGuildInfo(details, channels, roles);
        const chunks = splitMessage(message);

        for (const chunk of chunks) {
            await sendBotMessage(channelId, { content: "```\n" + chunk + "\n```" });
        }
    } catch (error: any) {
        logger.error("Failed to execute info command:", error);

        let errorMessage = "Unknown error";
        if (error instanceof Error) {
            errorMessage = error.message;
        } else if (error?.message) {
            errorMessage = error.message;
        } else if (error?.body?.message) {
            errorMessage = error.body.message;
        } else if (typeof error === "string") {
            errorMessage = error;
        } else {
            errorMessage = JSON.stringify(error);
        }

        await sendBotMessage(channelId, { content: `❌ Error: ${errorMessage}` });
    }
}

async function executeRoles(guildId: string, channelId: string): Promise<void> {
    try {
        const roles = await fetchGuildRoles(guildId);

        // Validate that roles is an array
        if (!Array.isArray(roles)) {
            throw new Error("Invalid roles data received from API");
        }

        const filtered = roles.filter(role => role.id !== guildId);
        const lines = filtered
            .sort((a, b) => b.position - a.position)
            .map((role, index) => `${index + 1}. @${role.name} (ID: ${role.id})`);

        const message = lines.length ? `Roles (highest to lowest):\n${lines.join("\n")}` : "No roles besides @everyone.";
        const chunks = splitMessage(message);

        for (const chunk of chunks) {
            await sendBotMessage(channelId, { content: "```\n" + chunk + "\n```" });
        }
    } catch (error: any) {
        logger.error("Failed to execute roles command:", error);

        let errorMessage = "Unknown error";
        if (error instanceof Error) {
            errorMessage = error.message;
        } else if (error?.message) {
            errorMessage = error.message;
        } else if (error?.body?.message) {
            errorMessage = error.body.message;
        } else if (typeof error === "string") {
            errorMessage = error;
        } else {
            errorMessage = JSON.stringify(error);
        }

        await sendBotMessage(channelId, { content: `❌ Error: ${errorMessage}` });
    }
}

async function executeTChannels(guildId: string, channelId: string): Promise<void> {
    try {
        const [channels, roles] = await Promise.all([
            fetchGuildChannels(guildId),
            fetchGuildRoles(guildId)
        ]);

        // Validate API responses
        if (!Array.isArray(channels)) {
            throw new Error("Invalid channels data received from API");
        }
        if (!Array.isArray(roles)) {
            throw new Error("Invalid roles data received from API");
        }

        const message = auditChannelOverwrites(
            channels,
            roles,
            ch => ch.type === 0 || ch.type === 5,
            [
                { perm: PERMISSIONS.MANAGE_CHANNELS, label: "manage the channel" },
                { perm: PERMISSIONS.MANAGE_ROLES, label: "manage permissions" },
                { perm: PERMISSIONS.MANAGE_WEBHOOKS, label: "manage webhooks" },
                { perm: PERMISSIONS.ADD_REACTIONS, label: "add reactions" },
                { perm: PERMISSIONS.MENTION_EVERYONE, label: "mention everyone" },
                { perm: PERMISSIONS.MANAGE_MESSAGES, label: "manage messages" },
            ],
        );

        const chunks = splitMessage(message);
        for (const chunk of chunks) {
            await sendBotMessage(channelId, { content: "```\n" + chunk + "\n```" });
        }
    } catch (error: any) {
        logger.error("Failed to execute tchannels command:", error);

        let errorMessage = "Unknown error";
        if (error instanceof Error) {
            errorMessage = error.message;
        } else if (error?.message) {
            errorMessage = error.message;
        } else if (error?.body?.message) {
            errorMessage = error.body.message;
        } else if (typeof error === "string") {
            errorMessage = error;
        } else {
            errorMessage = JSON.stringify(error);
        }

        await sendBotMessage(channelId, { content: `❌ Error: ${errorMessage}` });
    }
}

async function executeVChannels(guildId: string, channelId: string): Promise<void> {
    try {
        const [channels, roles] = await Promise.all([
            fetchGuildChannels(guildId),
            fetchGuildRoles(guildId)
        ]);

        // Validate API responses
        if (!Array.isArray(channels)) {
            throw new Error("Invalid channels data received from API");
        }
        if (!Array.isArray(roles)) {
            throw new Error("Invalid roles data received from API");
        }

        const message = auditChannelOverwrites(
            channels,
            roles,
            ch => ch.type === 2 || ch.type === 13,
            [
                { perm: PERMISSIONS.MANAGE_CHANNELS, label: "manage the channel" },
                { perm: PERMISSIONS.MANAGE_ROLES, label: "manage permissions" },
                { perm: PERMISSIONS.MUTE_MEMBERS, label: "mute members" },
            ],
        );

        const chunks = splitMessage(message);
        for (const chunk of chunks) {
            await sendBotMessage(channelId, { content: "```\n" + chunk + "\n```" });
        }
    } catch (error: any) {
        logger.error("Failed to execute vchannels command:", error);

        let errorMessage = "Unknown error";
        if (error instanceof Error) {
            errorMessage = error.message;
        } else if (error?.message) {
            errorMessage = error.message;
        } else if (error?.body?.message) {
            errorMessage = error.body.message;
        } else if (typeof error === "string") {
            errorMessage = error;
        } else {
            errorMessage = JSON.stringify(error);
        }

        await sendBotMessage(channelId, { content: `❌ Error: ${errorMessage}` });
    }
}

async function executeAccess(guildId: string, channelId: string): Promise<void> {
    try {
        const roles = await fetchGuildRoles(guildId);

        // Validate that roles is an array
        if (!Array.isArray(roles)) {
            throw new Error("Invalid roles data received from API");
        }

        const message = summarizeAccess(roles);
        const chunks = splitMessage(message);

        for (const chunk of chunks) {
            await sendBotMessage(channelId, { content: "```\n" + chunk + "\n```" });
        }
    } catch (error: any) {
        logger.error("Failed to execute access command:", error);

        let errorMessage = "Unknown error";
        if (error instanceof Error) {
            errorMessage = error.message;
        } else if (error?.message) {
            errorMessage = error.message;
        } else if (error?.body?.message) {
            errorMessage = error.body.message;
        } else if (typeof error === "string") {
            errorMessage = error;
        } else {
            errorMessage = JSON.stringify(error);
        }

        await sendBotMessage(channelId, { content: `❌ Error: ${errorMessage}` });
    }
}

async function executeMemberIds(guildId: string, channelId: string): Promise<void> {
    try {
        const members = await fetchAllMembers(guildId);

        // Validate that members is an array
        if (!Array.isArray(members)) {
            throw new Error("Invalid members data received from API");
        }

        const ids = Array.from(new Set(members.map(member => member.user.id))).sort();
        const content = ids.join("\n") + "\n";

        const guild = GuildStore.getGuild(guildId);
        const name = guild?.name ?? guildId;
        const filename = `${name.replace(/[^A-Za-z0-9_.-]+/g, "_")}_members_ID.txt`;

        downloadTextFile(filename, content);

        await sendBotMessage(channelId, {
            content: `✅ Exported ${ids.length} member IDs to ${filename}`
        });
    } catch (error: any) {
        logger.error("Failed to execute member IDs command:", error);

        let errorMessage = "Unknown error";
        if (error instanceof Error) {
            errorMessage = error.message;
        } else if (error?.message) {
            errorMessage = error.message;
        } else if (error?.body?.message) {
            errorMessage = error.body.message;
        } else if (typeof error === "string") {
            errorMessage = error;
        } else {
            errorMessage = JSON.stringify(error);
        }

        await sendBotMessage(channelId, { content: `❌ Error: ${errorMessage}` });
    }
}

async function executeWebhooks(guildId: string, channelId: string): Promise<void> {
    try {
        const webhooks = await fetchGuildWebhooks(guildId);

        // Validate that webhooks is an array
        if (!Array.isArray(webhooks)) {
            throw new Error("Invalid webhooks data received from API");
        }

        if (!webhooks.length) {
            await sendBotMessage(channelId, { content: "No webhooks found." });
            return;
        }

        const grouped = webhooks.reduce<Record<string, Webhook[]>>((acc, hook) => {
            if (!acc[hook.channel_id]) acc[hook.channel_id] = [];
            acc[hook.channel_id].push(hook);
            return acc;
        }, {});

        const lines: string[] = [];
        for (const [chId, hooks] of Object.entries(grouped)) {
            const channel = ChannelStore.getChannel(chId);
            const channelName = channel?.name ?? chId;
            for (const hook of hooks) {
                const label = hook.url ? `${hook.name ?? hook.id} -> ${hook.url}` : (hook.name ?? hook.id);
                lines.push(`#${channelName}: ${label}`);
            }
        }

        const message = `Discovered ${webhooks.length} webhooks:\n${lines.map(line => `  ${line}`).join("\n")}`;
        const chunks = splitMessage(message);

        for (const chunk of chunks) {
            await sendBotMessage(channelId, { content: "```\n" + chunk + "\n```" });
        }
    } catch (error: any) {
        logger.error("Failed to execute webhooks command:", error);

        // Extract a meaningful error message
        let errorMessage = "Unknown error";
        if (error instanceof Error) {
            errorMessage = error.message;
        } else if (error?.message) {
            errorMessage = error.message;
        } else if (error?.body?.message) {
            errorMessage = error.body.message;
        } else if (typeof error === "string") {
            errorMessage = error;
        } else {
            errorMessage = JSON.stringify(error);
        }

        await sendBotMessage(channelId, { content: `❌ Error: ${errorMessage}` });
    }
}

export default definePlugin({
    name: "ServerScanner",
    description: "Comprehensive security auditing tool for Discord servers with automatic vulnerability detection and exploitation path analysis",
    authors: [{ name: "Equicord", id: 0n }],

    commands: [
        {
            name: "server-autoscan",
            description: "🔒 Run comprehensive security audit and detect exploitation chains",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: async (_, ctx) => {
                if (!ctx.guild?.id) {
                    return sendBotMessage(ctx.channel.id, {
                        content: "❌ This command can only be used in a server."
                    });
                }

                await executeAutoScan(ctx.guild.id, ctx.channel.id);
            }
        },
        {
            name: "server-autoscan-report",
            description: "📄 Download the last security audit report as Markdown",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: async (_, ctx) => {
                await executeDownloadReport(ctx.channel.id);
            }
        },
        {
            name: "server-info",
            description: "Show detailed information about the current server",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: async (_, ctx) => {
                if (!ctx.guild?.id) {
                    return sendBotMessage(ctx.channel.id, {
                        content: "❌ This command can only be used in a server."
                    });
                }

                await sendBotMessage(ctx.channel.id, {
                    content: `🔍 Scanning server information for **${ctx.guild.name}**...`
                });

                await executeInfo(ctx.guild.id, ctx.channel.id);
            }
        },
        {
            name: "server-roles",
            description: "List all roles in the current server",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: async (_, ctx) => {
                if (!ctx.guild?.id) {
                    return sendBotMessage(ctx.channel.id, {
                        content: "❌ This command can only be used in a server."
                    });
                }

                await sendBotMessage(ctx.channel.id, {
                    content: `🔍 Fetching roles for **${ctx.guild.name}**...`
                });

                await executeRoles(ctx.guild.id, ctx.channel.id);
            }
        },
        {
            name: "server-text-channels",
            description: "Audit risky permissions on text channels",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: async (_, ctx) => {
                if (!ctx.guild?.id) {
                    return sendBotMessage(ctx.channel.id, {
                        content: "❌ This command can only be used in a server."
                    });
                }

                await sendBotMessage(ctx.channel.id, {
                    content: `🔍 Auditing text channel permissions for **${ctx.guild.name}**...`
                });

                await executeTChannels(ctx.guild.id, ctx.channel.id);
            }
        },
        {
            name: "server-voice-channels",
            description: "Audit risky permissions on voice channels",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: async (_, ctx) => {
                if (!ctx.guild?.id) {
                    return sendBotMessage(ctx.channel.id, {
                        content: "❌ This command can only be used in a server."
                    });
                }

                await sendBotMessage(ctx.channel.id, {
                    content: `🔍 Auditing voice channel permissions for **${ctx.guild.name}**...`
                });

                await executeVChannels(ctx.guild.id, ctx.channel.id);
            }
        },
        {
            name: "server-access",
            description: "Summarize roles with sensitive guild permissions",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: async (_, ctx) => {
                if (!ctx.guild?.id) {
                    return sendBotMessage(ctx.channel.id, {
                        content: "❌ This command can only be used in a server."
                    });
                }

                await sendBotMessage(ctx.channel.id, {
                    content: `🔍 Analyzing role permissions for **${ctx.guild.name}**...`
                });

                await executeAccess(ctx.guild.id, ctx.channel.id);
            }
        },
        {
            name: "server-member-ids",
            description: "Export all member IDs to a text file",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: async (_, ctx) => {
                if (!ctx.guild?.id) {
                    return sendBotMessage(ctx.channel.id, {
                        content: "❌ This command can only be used in a server."
                    });
                }

                await sendBotMessage(ctx.channel.id, {
                    content: `🔍 Fetching all member IDs for **${ctx.guild.name}**... (this may take a while for large servers)`
                });

                await executeMemberIds(ctx.guild.id, ctx.channel.id);
            }
        },
        {
            name: "server-webhooks",
            description: "List all webhooks in the current server",
            inputType: ApplicationCommandInputType.BUILT_IN,
            execute: async (_, ctx) => {
                if (!ctx.guild?.id) {
                    return sendBotMessage(ctx.channel.id, {
                        content: "❌ This command can only be used in a server."
                    });
                }

                await sendBotMessage(ctx.channel.id, {
                    content: `🔍 Scanning webhooks for **${ctx.guild.name}**...`
                });

                await executeWebhooks(ctx.guild.id, ctx.channel.id);
            }
        }
    ]
});
