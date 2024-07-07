
rule Trojan_Win32_Zbot_RH_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 8b 08 03 4d 10 8b 55 08 03 55 fc 66 89 0a 8b 45 f8 c1 e8 04 89 45 f8 8b 4d f8 83 e9 01 89 4d f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zbot_RH_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 00 43 00 3a 00 5c 00 4d 00 61 00 78 00 5c 00 59 00 4c 00 49 00 51 00 63 00 5c 00 4d 00 79 00 65 00 76 00 6a 00 2e 00 76 00 62 00 70 00 } //1 AC:\Max\YLIQc\Myevj.vbp
		$a_01_1 = {45 3e d6 ba 63 25 5c 9c 2d 24 20 15 6f a3 9e b3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}