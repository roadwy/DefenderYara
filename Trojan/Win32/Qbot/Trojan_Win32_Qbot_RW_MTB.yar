
rule Trojan_Win32_Qbot_RW_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 80 0d 00 00 03 05 90 01 04 a3 90 01 04 a1 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 83 05 90 01 04 04 a1 90 01 04 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RW_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 8b 55 90 01 01 03 55 90 01 01 03 55 90 01 01 33 c2 03 d8 68 8c 10 00 00 6a 00 e8 90 01 04 03 d8 68 8c 10 00 00 6a 00 e8 90 01 04 03 d8 68 8c 10 00 00 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RW_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 8b 55 90 01 01 03 55 90 01 01 03 55 90 01 01 33 c2 03 d8 68 57 15 00 00 6a 00 e8 90 01 04 03 d8 68 57 15 00 00 6a 00 e8 90 01 04 03 d8 68 57 15 00 00 6a 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RW_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 5c 0e 00 00 6a 00 e8 90 01 04 8b d8 a1 90 01 04 8b 00 8b 15 90 01 04 03 55 90 01 01 03 55 90 01 01 33 c2 03 d8 68 5c 0e 00 00 6a 00 e8 90 01 04 03 d8 68 5c 0e 00 00 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RW_MTB_5{
	meta:
		description = "Trojan:Win32/Qbot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 03 d8 68 90 01 04 6a 90 01 01 e8 90 01 04 03 d8 90 00 } //1
		$a_02_1 = {03 d8 8b 45 90 01 01 31 18 68 90 01 04 e8 90 01 04 68 90 01 04 e8 90 01 04 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 0f 82 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}