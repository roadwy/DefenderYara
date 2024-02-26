
rule Trojan_BAT_Redline_NL_MTB{
	meta:
		description = "Trojan:BAT/Redline.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {73 29 00 00 0a 0a 06 20 e8 03 00 00 20 b8 0b 00 00 6f 2a 00 00 0a 28 2b 00 00 0a 00 72 b5 00 00 70 28 12 00 00 06 00 06 20 e8 03 00 00 20 b8 0b 00 00 6f 2a 00 00 0a 28 2b 00 00 0a 00 72 f7 00 00 70 28 12 00 00 06 } //00 00 
	condition:
		any of ($a_*)
 
}