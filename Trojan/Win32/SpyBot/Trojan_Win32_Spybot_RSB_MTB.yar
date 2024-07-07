
rule Trojan_Win32_Spybot_RSB_MTB{
	meta:
		description = "Trojan:Win32/Spybot.RSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {34 d7 fe c0 34 5b 04 4f 34 de fe c0 2c 7d 04 cf fe c8 34 f1 04 02 fe c0 fe c0 fe c0 fe c8 34 b7 88 84 0d 90 01 04 83 c1 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Spybot_RSB_MTB_2{
	meta:
		description = "Trojan:Win32/Spybot.RSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c1 01 eb 90 0a 6f 00 8a 84 0d 90 01 04 81 f9 90 01 04 74 90 02 0f 34 90 02 0f 34 90 02 0f 34 90 02 0f 34 90 02 0f 34 90 02 1f 88 84 0d 90 1b 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Spybot_RSB_MTB_3{
	meta:
		description = "Trojan:Win32/Spybot.RSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 83 c1 01 eb 90 01 01 b0 00 b9 00 00 00 00 8d 45 f8 50 6a 40 90 0a 2f 00 34 90 01 05 2c 90 02 0a 88 84 0d 90 00 } //1
		$a_03_1 = {8a 04 39 88 07 8d 7f 01 4e 75 90 0a 1f 00 be 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}