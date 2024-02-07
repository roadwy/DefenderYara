
rule Trojan_BAT_RedLineStealer_MGA_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 75 79 20 26 20 73 65 6c 6c 20 43 72 79 70 74 6f 20 69 6e 20 6d 69 6e 75 74 65 73 2c 20 6a 6f 69 6e 20 74 68 65 20 77 6f 72 6c 64 } //01 00  Buy & sell Crypto in minutes, join the world
		$a_01_1 = {6c 61 72 67 65 73 74 20 63 72 79 70 74 6f 20 65 78 63 68 61 6e 67 65 } //01 00  largest crypto exchange
		$a_01_2 = {53 6b 69 70 53 65 63 75 72 69 74 79 43 68 65 63 6b 73 52 65 6d 6f 74 69 6e 67 53 65 72 76 69 63 65 73 } //01 00  SkipSecurityChecksRemotingServices
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {2f 39 50 41 77 34 66 78 75 50 70 72 53 44 } //01 00  /9PAw4fxuPprSD
		$a_01_5 = {44 65 62 75 67 67 65 72 53 74 65 70 70 65 72 42 6f 75 6e 64 61 72 79 41 74 74 72 69 62 75 74 65 67 65 74 4d 44 } //01 00  DebuggerStepperBoundaryAttributegetMD
		$a_01_6 = {67 65 74 5f 50 72 6f 78 79 52 65 76 61 6c 69 64 61 74 65 } //01 00  get_ProxyRevalidate
		$a_01_7 = {4c 6f 63 6b 65 64 46 72 6f 6d 42 61 73 65 53 74 72 69 6e 67 } //01 00  LockedFromBaseString
		$a_01_8 = {4b 6f 72 65 61 6e 45 72 61 45 6e 64 50 72 6f 6c 6f 67 } //01 00  KoreanEraEndProlog
		$a_01_9 = {53 6c 65 65 70 } //00 00  Sleep
	condition:
		any of ($a_*)
 
}