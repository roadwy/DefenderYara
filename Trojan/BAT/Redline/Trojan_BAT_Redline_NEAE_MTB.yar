
rule Trojan_BAT_Redline_NEAE_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0a 03 07 03 6f 5d 00 00 0a 5d 6f 37 00 00 0a 61 0c 06 72 63 08 00 70 08 28 a4 00 00 0a 6f a5 00 00 0a 26 00 07 17 58 0b 07 02 6f 5d 00 00 0a fe 04 0d 09 2d c4 } //00 00 
	condition:
		any of ($a_*)
 
}