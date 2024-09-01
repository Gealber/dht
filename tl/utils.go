package tl

import "strconv"

// getConstructor extract the constructor from the TL definition specified.
func getConstructor(tlDef string) string {
	i := 0
	for tlDef[i] != ' ' {
		i++
	}

	return tlDef[:i]
}

// getCombinator extract the combinator from the TL definition specified.
func getCombinator(tlDef string) string {
	i := len(tlDef) - 1
	for tlDef[i] != ' ' {
		i--
	}

	return tlDef[i+1:]
}

// extractTypes extract the types in TL definition in the order they are defined.
func extractTypes(tlDef string) []string {
	result := make([]string, 0)
	i := 0
	start := -1
	insideExpr := 0
	for i < len(tlDef) {
		if tlDef[i] == ':' {
			start = i + 1
		}

		if tlDef[i] == '(' {
			insideExpr++
		}

		if tlDef[i] == ')' {
			insideExpr--
		}

		if start != -1 && tlDef[i] == ' ' && insideExpr == 0 {
			result = append(result, tlDef[start:i])
			start = -1
		}
		i++
	}

	return result
}

// extractOptionalBitPosition given a TL type extract the bit position in 'flags' if present.
// For example: 'flags.3?PublicKey', should return 3. In case is not present -1 should be returned.
func extractOptionalBitPosition(t string) int {
	if len(t) <= 6 {
		// should have at least 6 characters for 'flags.'
		return -1
	}

	if t[:6] != "flags." {
		return -1
	}

	t = t[6:]

	val := ""
	start := 0
	for i := 0; i < len(t); i++ {
		if t[i] == '?' {
			val = t[start:i]
			break
		}
	}

	if val != "" {
		result, err := strconv.Atoi(val)
		if err != nil {
			return -1
		}

		return result
	}

	return -1
}
