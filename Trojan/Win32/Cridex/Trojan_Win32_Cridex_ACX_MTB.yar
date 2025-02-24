
rule Trojan_Win32_Cridex_ACX_MTB{
	meta:
		description = "Trojan:Win32/Cridex.ACX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 d9 89 5d f8 8b 45 f8 c1 e8 03 b9 01 00 00 00 2b c8 89 4d dc 8b 55 f8 0f af 55 dc 89 55 f8 c1 e3 03 8b 45 ec 03 45 fc 0f b6 08 03 4d f4 8b 55 ec 03 55 fc 88 0a 8b 45 fc 83 e8 01 89 45 fc 8b 4d fc 83 e9 01 89 4d fc 8b 55 fc } //3
		$a_01_1 = {83 c0 02 89 45 fc 8b 4d e0 03 4d fc 8a 51 01 88 55 eb 8b 45 fc 83 c0 01 89 45 fc 8a 4d eb 88 4d f3 8b 55 ec 03 55 fc 8a 45 f3 88 02 8b 4d 14 03 4d f8 0f b6 11 89 55 f4 8b 5d f8 8b 4d d4 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}