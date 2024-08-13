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
