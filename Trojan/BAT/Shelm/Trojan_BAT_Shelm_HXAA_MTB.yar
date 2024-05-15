
rule Trojan_BAT_Shelm_HXAA_MTB{
	meta:
		description = "Trojan:BAT/Shelm.HXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 00 06 04 6f 90 01 01 00 00 0a 00 06 06 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b 73 90 01 01 00 00 0a 0c 00 08 07 17 73 90 01 01 00 00 0a 0d 00 09 02 16 02 8e 69 6f 90 01 01 00 00 0a 00 00 de 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}