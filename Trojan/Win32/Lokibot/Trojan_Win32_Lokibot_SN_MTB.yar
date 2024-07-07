
rule Trojan_Win32_Lokibot_SN_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 00 88 45 fb 90 02 04 8a 45 fb 32 45 fa 8b 55 fc 88 02 ff 45 f4 81 7d f4 90 00 } //1
		$a_03_1 = {c7 45 e0 01 00 00 00 6a 00 6a 00 e8 90 01 04 ff 45 e0 81 7d e0 90 01 04 75 90 01 01 89 ff 89 ff 89 ff e8 90 01 04 89 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Lokibot_SN_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 03 55 f4 90 05 10 01 90 8a 03 90 05 10 01 90 34 90 01 01 90 05 10 01 90 88 02 90 05 10 01 90 8d 45 f4 e8 90 01 04 90 05 10 01 90 43 4e 75 90 00 } //3
		$a_03_1 = {8b 45 f8 03 45 f4 90 05 10 01 90 8a 13 90 05 10 01 90 80 f2 90 01 01 90 05 10 01 90 88 10 90 05 10 01 90 8d 45 f4 e8 90 01 04 90 05 10 01 90 43 4e 75 90 00 } //3
		$a_03_2 = {8b c2 03 c3 90 05 10 01 90 c6 00 90 01 01 90 05 10 01 90 43 81 fb 90 01 04 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_03_2  & 1)*1) >=4
 
}