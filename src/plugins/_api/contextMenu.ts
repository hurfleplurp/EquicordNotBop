/*
 * Vencord, a modification for Discord's desktop app
 * Copyright (c) 2022 Vendicated and contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import { Devs } from "@utils/constants";
import definePlugin from "@utils/types";

export default definePlugin({
    name: "ContextMenuAPI",
    description: "API for adding/removing items to/from context menus.",
    authors: [Devs.Nuckyz, Devs.Ven, Devs.Kyuuhachi],
    required: true,

    patches: [
        {
            find: "♫ (つ｡◕‿‿◕｡)つ ♪",
            replacement: {
                match: /(?=let{navId:)(?<=function \i\((\i)\).+?)/,
                replace: "$1=Vencord.Api.ContextMenu._usePatchContextMenu($1);"
            }
        },
        {
            find: "navId:",
            all: true,
            noWarn: true,
            replacement: [
                {
                    match: /navId:\s*(["'])(.+?)\1(?=[\s\S]+?([,}][\s\S]*?\)))/g,
                    replace: (m, quote, navId, rest) => {
                        const destructuringMatch = rest.match(/}=.+/);
                        if (destructuringMatch == null) {
                            // Only inject arguments for known safe context menus to avoid "arguments is not allowed in class field initializer" syntax error
                            // "expression-picker" is for the sticker picker / emoji picker
                            const SafeNavIds = [
                                "textarea-context",
                                "channel-context",
                                "message", // "message" is sometimes used without -context suffix
                                "message-context",
                                "user-context",
                                "guild-context",
                                "thread-context",
                                "expression-picker",
                                "image-context",
                                "gdm-context"
                            ];

                            if (SafeNavIds.includes(navId) || SafeNavIds.some(safe => navId.startsWith(safe))) {
                                return `contextMenuAPIArguments:typeof arguments!=='undefined'?arguments:[],${m}`;
                            }

                            return `contextMenuAPIArguments:[],${m}`;
                        }
                        return m;
                    }
                }
            ]
        }
    ]
});
