
rule VirTool_BAT_CryptInject_PB_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {41 50 79 5a 74 79 61 00 00 [0-20] 41 50 79 5a 74 79 61 20 49 6e 63 00 00 } //1
		$a_00_1 = {46 67 42 4a 46 58 54 68 2e 65 78 65 } //1 FgBJFXTh.exe
		$a_00_2 = {53 6b 69 70 56 65 72 69 66 69 63 61 74 69 6f 6e } //1 SkipVerification
		$a_00_3 = {73 51 4f 6d 67 66 61 57 4a 79 47 78 52 79 79 4c 6c 66 45 62 } //1 sQOmgfaWJyGxRyyLlfEb
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}