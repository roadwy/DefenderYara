
rule Trojan_Win32_Vidar_RAN_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 ca 0f b6 c9 89 4d f8 8b 4c 88 08 89 4c b8 08 02 ca 89 7d 90 01 01 8b 7d f8 0f b6 c9 89 54 b8 08 89 55 fc 0f b6 54 88 08 30 56 04 83 c6 06 ff 4d f0 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}