
rule Trojan_BAT_Vidar_GFT_MTB{
	meta:
		description = "Trojan:BAT/Vidar.GFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 06 16 73 90 01 03 0a 0c 00 02 8e 69 8d 90 01 03 01 0d 08 09 16 09 8e 69 6f 90 01 03 0a 13 04 09 11 04 28 90 01 03 2b 28 90 01 03 2b 13 05 de 21 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}