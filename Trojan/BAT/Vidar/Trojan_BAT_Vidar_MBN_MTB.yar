
rule Trojan_BAT_Vidar_MBN_MTB{
	meta:
		description = "Trojan:BAT/Vidar.MBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 0c 08 06 7d 90 01 01 00 00 04 00 07 7e 90 01 01 00 00 04 6f 90 01 01 00 00 0a 00 07 18 6f 90 01 01 00 00 0a 00 07 18 6f 90 01 01 00 00 0a 00 08 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}