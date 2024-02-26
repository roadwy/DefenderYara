
rule Trojan_BAT_Vidar_PTAO_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PTAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 02 20 a0 00 00 00 28 90 01 01 00 00 06 28 90 01 01 00 00 06 20 04 00 00 00 38 a5 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}