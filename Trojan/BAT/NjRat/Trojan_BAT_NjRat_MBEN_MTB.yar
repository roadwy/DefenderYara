
rule Trojan_BAT_NjRat_MBEN_MTB{
	meta:
		description = "Trojan:BAT/NjRat.MBEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {1f 23 28 ee 00 00 0a 72 0b 16 00 70 } //1
		$a_01_1 = {45 00 46 00 6f 00 41 00 53 00 41 00 41 00 41 00 45 00 63 00 74 00 38 00 41 00 41 00 48 00 43 00 41 00 45 00 77 00 41 00 41 00 42 00 42 00 53 00 41 00 46 00 41 00 41 00 41 00 42 00 48 } //1
		$a_01_2 = {46 42 5f 43 68 65 63 6b 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 FB_Checker.Resources.resource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}