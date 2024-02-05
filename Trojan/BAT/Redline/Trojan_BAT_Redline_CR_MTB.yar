
rule Trojan_BAT_Redline_CR_MTB{
	meta:
		description = "Trojan:BAT/Redline.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 72 05 00 00 70 73 90 01 01 00 00 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b 16 0c 2b 21 90 00 } //01 00 
		$a_01_1 = {61 70 70 62 75 6e 64 6c 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}