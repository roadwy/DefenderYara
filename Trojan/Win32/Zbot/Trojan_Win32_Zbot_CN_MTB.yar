
rule Trojan_Win32_Zbot_CN_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 d9 41 f7 e1 89 85 [0-04] 33 85 [0-04] 8b 95 [0-04] 89 02 83 c6 08 83 45 f8 08 83 c6 fc 83 45 f8 fc 83 3e 00 75 94 } //1
		$a_01_1 = {89 f9 89 da d3 fa 29 d7 8b 55 e8 29 fa 89 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}