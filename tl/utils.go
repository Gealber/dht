package tl

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
	for i < len(tlDef) {
		if tlDef[i] == ':' {
			start = i + 1
		}

		if start != -1 && tlDef[i] == ' ' {
			result = append(result, tlDef[start:i])
			start = -1
		}
		i++
	}

	return result
}
