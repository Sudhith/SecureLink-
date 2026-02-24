/**
 * example-claude-bot.js
 * ─────────────────────────────────────────────────────────────
 * Example: integrate Nexus Scanner as a tool in a Claude chatbot.
 *
 * This shows how Claude can autonomously scan URLs when users ask.
 *
 * Run: node example-claude-bot.js
 * ─────────────────────────────────────────────────────────────
 */

import Anthropic from '@anthropic-ai/sdk';
import { CLAUDE_TOOL_DEFINITION, handleClaudeToolCall } from './chatbot-integration.js';
import 'dotenv/config';

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

/**
 * Chat with Claude — it will automatically use Nexus to scan URLs.
 * @param {string} userMessage
 */
async function chat(userMessage) {
  console.log(`\nUser: ${userMessage}`);

  const messages = [{ role: 'user', content: userMessage }];

  // First call — Claude may decide to use the scan_url tool
  let response = await client.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 1024,
    system: `You are a helpful security assistant with access to a URL scanning tool.
When users share links or ask about URL safety, use the scan_url tool to check them.
Always present results clearly and advise the user whether to visit the URL.`,
    tools: [CLAUDE_TOOL_DEFINITION],
    messages,
  });

  // Agentic loop — handle tool calls
  while (response.stop_reason === 'tool_use') {
    const assistantMsg = { role: 'assistant', content: response.content };
    messages.push(assistantMsg);

    const toolResults = [];

    for (const block of response.content) {
      if (block.type === 'tool_use') {
        console.log(`\n  [Tool call] scan_url("${block.input.url}")`);
        const result = await handleClaudeToolCall(block.input);
        console.log(`  [Tool result] ${result.slice(0, 120)}…`);

        toolResults.push({
          type: 'tool_result',
          tool_use_id: block.id,
          content: result,
        });
      }
    }

    messages.push({ role: 'user', content: toolResults });

    // Follow-up call with tool results
    response = await client.messages.create({
      model: 'claude-opus-4-6',
      max_tokens: 1024,
      system: messages[0].content, // reuse system prompt
      tools: [CLAUDE_TOOL_DEFINITION],
      messages: messages.slice(1), // skip system in messages array
    });
  }

  // Extract final text response
  const reply = response.content
    .filter(b => b.type === 'text')
    .map(b => b.text)
    .join('');

  console.log(`\nAssistant: ${reply}`);
  return reply;
}

// ── Demo ─────────────────────────────────────────────────────
(async () => {
  await chat('Can you check if https://google.com is safe?');
  await chat('Is this link dangerous? https://example.com/download');
})();
