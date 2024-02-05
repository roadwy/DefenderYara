
rule Trojan_Win32_Vidar_BD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {0f b6 d1 8d 04 32 0f b6 f0 8a 84 35 fc fe ff ff 88 84 3d fc fe ff ff 8b 45 fc 88 8c 35 fc fe ff ff 0f b6 8c 3d fc fe ff ff 03 ca 0f b6 c9 8a 8c 0d fc fe ff ff 30 0b 43 85 c0 75 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 } //00 00 
	condition:
		any of ($a_*)
 
}