
rule Trojan_Win32_Glupteba_YAH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.YAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 04 13 d3 ea 89 45 dc c7 05 90 01 08 03 55 e0 8b 45 dc 31 45 fc 33 55 fc 89 55 dc 8b 45 dc 83 45 f8 64 29 45 f8 83 6d f8 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}