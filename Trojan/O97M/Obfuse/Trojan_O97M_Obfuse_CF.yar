
rule Trojan_O97M_Obfuse_CF{
	meta:
		description = "Trojan:O97M/Obfuse.CF,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 6f 62 22 20 2b 20 4f 52 7a 57 63 6a 71 7a 46 49 6b 59 69 64 20 2b 20 6d 62 6f 47 4f 48 4f 77 55 4c 4e 20 2b 20 22 6a 45 43 22 20 2b 20 76 77 6d 64 6a 51 44 49 49 42 66 4a 20 2b 20 61 6b 4a 4f 77 5a 6b 43 20 2b 20 22 54 22 20 2b 20 70 66 47 43 77 43 52 57 20 2b 20 4b 4a 77 76 75 4e 59 57 20 2b 20 22 20 20 22 20 2b 20 4a 77 4a 7a 6f 4f 4b 77 51 7a 41 20 2b 20 62 6e 44 4a 41 4b 47 6b 4a 70 73 41 51 6d 20 2b 20 22 53 59 22 20 2b 20 6a 42 4f 59 59 42 73 57 4a 4f 20 2b 20 55 46 56 4d 51 4b 57 48 71 44 58 4d 58 20 2b 20 22 73 54 22 20 2b 20 47 52 77 58 62 77 63 20 2b 20 6c 55 61 5a 76 68 41 6d 61 4f 50 44 55 66 20 2b 20 22 45 6d 2e 22 } //01 00  "ob" + ORzWcjqzFIkYid + mboGOHOwULN + "jEC" + vwmdjQDIIBfJ + akJOwZkC + "T" + pfGCwCRW + KJwvuNYW + "  " + JwJzoOKwQzA + bnDJAKGkJpsAQm + "SY" + jBOYYBsWJO + UFVMQKWHqDXMX + "sT" + GRwXbwc + lUaZvhAmaOPDUf + "Em."
		$a_01_1 = {53 68 65 6c 6c 28 70 48 75 70 61 71 5a 6c 55 69 72 7a 54 2c 20 31 35 39 36 39 35 33 32 37 20 2d 20 31 35 39 36 39 35 33 32 37 29 } //00 00  Shell(pHupaqZlUirzT, 159695327 - 159695327)
	condition:
		any of ($a_*)
 
}