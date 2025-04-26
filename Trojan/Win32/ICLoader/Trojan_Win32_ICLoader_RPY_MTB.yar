
rule Trojan_Win32_ICLoader_RPY_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 30 8b 04 24 50 89 e0 05 04 00 00 00 51 b9 04 00 00 00 01 c8 59 33 04 24 31 04 24 33 04 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ICLoader_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/ICLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 96 84 00 85 f5 80 00 00 da 0a 00 73 5b 0d ca 36 b8 80 00 00 d4 00 00 f8 3c 15 20 } //1
		$a_01_1 = {58 00 52 00 45 00 43 00 4f 00 44 00 45 00 20 00 33 00 } //1 XRECODE 3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_ICLoader_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/ICLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 55 6c 00 fa b3 68 00 00 da 0a 00 73 5b 0d ca 37 3e 68 00 00 d4 00 00 4d 7d f5 28 } //1
		$a_01_1 = {41 00 75 00 64 00 69 00 6f 00 53 00 77 00 69 00 74 00 63 00 68 00 } //1 AudioSwitch
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_ICLoader_RPY_MTB_4{
	meta:
		description = "Trojan:Win32/ICLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {14 64 74 00 8b c8 70 00 00 be 0a 00 0b 33 49 b9 78 81 70 00 00 dc 01 00 6a 8d 5e 14 } //10
		$a_01_1 = {ba 73 74 00 31 d8 70 00 00 be 0a 00 0b 33 49 b9 10 91 70 00 00 dc 01 00 80 f1 86 03 } //10
		$a_01_2 = {44 00 54 00 50 00 61 00 6e 00 65 00 6c 00 51 00 54 00 } //1 DTPanelQT
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}