
rule Trojan_Win32_Vidar_AV_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 39 45 10 76 90 01 01 8b 55 fc 8b 45 f4 01 d0 8b 4d fc 8b 55 f8 01 ca 0f b6 00 88 02 83 45 fc 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}