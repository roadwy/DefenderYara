
rule Trojan_BAT_Steam_AMQ_MTB{
	meta:
		description = "Trojan:BAT/Steam.AMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {2d 1b 26 02 06 90 01 01 2d 18 26 26 06 02 7b 90 01 01 00 00 0a 7b 90 01 01 00 00 0a fe 01 16 fe 01 2b 0a 0a 2b e3 7d 90 01 01 00 00 0a 2b e3 2a 90 00 } //10
		$a_80_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //ToBase64String  3
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  3
		$a_80_3 = {43 69 70 68 65 72 4d 6f 64 65 } //CipherMode  3
		$a_80_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //DebuggerHiddenAttribute  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}