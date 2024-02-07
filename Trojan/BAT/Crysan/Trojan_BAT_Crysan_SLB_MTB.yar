
rule Trojan_BAT_Crysan_SLB_MTB{
	meta:
		description = "Trojan:BAT/Crysan.SLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_1 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_81_2 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_81_3 = {57 69 6e 64 6f 77 73 41 70 70 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //05 00  WindowsApps.Resources.resources
		$a_80_4 = {70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 66 38 4c 35 37 46 4e 31 } //pastebin.com/raw/f8L57FN1  00 00 
	condition:
		any of ($a_*)
 
}