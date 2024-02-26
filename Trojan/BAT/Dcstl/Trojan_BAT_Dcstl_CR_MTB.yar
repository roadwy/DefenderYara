
rule Trojan_BAT_Dcstl_CR_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 19 00 00 70 6f 90 01 03 06 00 06 72 90 01 03 70 02 7b 90 01 03 04 6f 90 01 03 0a 72 90 01 03 70 02 7b 90 01 03 04 6f 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {52 6f 7a 62 65 68 54 68 65 52 6f 62 62 65 72 } //01 00  RozbehTheRobber
		$a_01_2 = {41 00 64 00 77 00 61 00 72 00 65 00 20 00 48 00 4f 00 41 00 58 00 } //01 00  Adware HOAX
		$a_01_3 = {43 6f 6e 63 61 74 } //01 00  Concat
		$a_01_4 = {44 63 57 65 62 48 6f 6f 6b } //00 00  DcWebHook
	condition:
		any of ($a_*)
 
}