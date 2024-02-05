
rule Trojan_BAT_Redline_NEAX_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {02 28 15 00 00 0a 72 01 00 00 70 28 16 00 00 0a 2d 22 73 17 00 00 0a 0a 06 72 57 00 00 70 72 01 00 00 70 6f 18 00 00 0a de 0a 06 2c 06 06 6f 19 00 00 0a dc 72 01 00 00 70 28 1a 00 00 0a 26 16 } //00 00 
	condition:
		any of ($a_*)
 
}