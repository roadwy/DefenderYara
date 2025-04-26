
rule Trojan_Win32_Zbot_BAC_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 4d f0 8b 11 33 55 ec 8b 45 08 03 45 f0 89 10 e9 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win32_Zbot_BAC_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 4f bf 50 34 68 54 31 06 5b 0a 0e 8b a6 f4 7e a1 cb 5f 6d ec b0 75 ac 44 53 98 8d 9b 56 24 fc 3d 4a c1 bc 7d b2 f8 b3 68 b6 b4 aa 15 19 89 f9 f8 53 a0 c7 4a 72 ea 59 5c 75 } //2
		$a_01_1 = {a9 72 14 9e 09 3c 4a f9 a3 00 ca 74 40 23 60 8f 82 37 c9 3b 1f 6e 1b 48 0f 66 eb } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}