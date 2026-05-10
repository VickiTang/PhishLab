package com.phishlab.web;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 简单的 JSON 工具类，不引入外部库。
 */
public class JsonUtil {

    /**
     * 转义 JSON 特殊字符：双引号、反斜杠、换行符 (\n)、回车符 (\r)、制表符 (\t)
     */
    public static String escape(String s) {
        if (s == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    sb.append(ch);
            }
        }
        return sb.toString();
    }

    /**
     * 返回 escape 后用双引号包裹的字符串
     */
    public static String quote(String s) {
        return "\"" + escape(s) + "\"";
    }

    /**
     * 接受偶数个参数，构造 JSON 对象字符串。
     * 键会自动 quote，值按原样填充。
     */
    public static String obj(String... keyValuePairs) {
        if (keyValuePairs.length % 2 != 0) {
            throw new IllegalArgumentException("keyValuePairs must have an even number of elements");
        }
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < keyValuePairs.length; i += 2) {
            if (i > 0) {
                sb.append(",");
            }
            sb.append(quote(keyValuePairs[i]));
            sb.append(":");
            sb.append(keyValuePairs[i + 1]);
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * 接受字符串列表（每个 item 已经是合法 JSON 片段），返回 [item1,item2,...]
     */
    public static String arr(List<String> items) {
        return "[" + String.join(",", items) + "]";
    }

    /**
     * 接受普通字符串列表，每个 item 自动 quote，返回 ["a","b","c"]
     */
    public static String quotedArr(List<String> items) {
        List<String> quoted = items.stream()
                .map(JsonUtil::quote)
                .collect(Collectors.toList());
        return arr(quoted);
    }

    public static void main(String[] args) {
        System.out.println("===== JsonUtil デモ =====");
        System.out.println("escape(\"hello\\\"world\\n\"): " + escape("hello\"world\n"));
        System.out.println("quote(\"test\"): " + quote("test"));
        System.out.println("obj(\"a\", quote(\"1\"), \"b\", \"2\"): " + obj("a", quote("1"), "b", "2"));
        System.out.println("quotedArr([\"x\",\"y\",\"z\"]): " + quotedArr(java.util.Arrays.asList("x", "y", "z")));
    }
}
