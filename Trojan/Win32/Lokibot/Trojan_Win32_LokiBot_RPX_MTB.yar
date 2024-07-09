
rule Trojan_Win32_LokiBot_RPX_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 83 c2 01 89 55 fc 81 7d fc da 16 00 00 7d 27 8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 e4 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb c7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LokiBot_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 65 c4 00 83 7d c4 01 73 06 83 65 a8 00 eb 08 e8 ?? ?? ?? ?? 89 45 a8 ba ?? ?? ?? ?? 8b 45 c4 8b 4d e4 8d 0c 81 e8 ?? ?? ?? ?? ff 75 c0 ff 75 bc ff 75 b8 ff 75 b4 8d 45 cc 50 e8 ?? ?? ?? ?? 89 45 ac 83 7d ac 00 75 b7 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}