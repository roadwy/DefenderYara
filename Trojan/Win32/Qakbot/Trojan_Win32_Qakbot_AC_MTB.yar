
rule Trojan_Win32_Qakbot_AC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {41 46 76 53 72 75 } //3 AFvSru
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //3 DllRegisterServer
		$a_81_2 = {45 4b 56 6d 74 6e } //3 EKVmtn
		$a_81_3 = {45 78 78 58 62 6a 75 6f } //3 ExxXbjuo
		$a_81_4 = {53 74 72 52 65 74 54 6f 53 74 72 41 } //3 StrRetToStrA
		$a_81_5 = {53 74 72 52 65 74 54 6f 42 75 66 57 } //3 StrRetToBufW
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}
rule Trojan_Win32_Qakbot_AC_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 4b 6a 00 e8 90 02 04 03 d8 6a 00 e8 90 02 04 03 d8 a1 90 02 04 33 18 89 1d 90 02 04 6a 00 e8 90 02 04 03 05 90 02 04 8b 15 90 02 04 89 02 a1 90 02 04 83 c0 04 a3 90 02 04 33 c0 a3 90 02 04 a1 90 02 04 83 c0 04 03 05 90 02 04 a3 90 02 04 a1 90 02 04 3b 05 90 02 04 0f 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Qakbot_AC_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 3a c0 74 90 01 01 83 f8 46 7e 90 01 01 83 65 fc 00 eb 90 01 01 3a ed 74 90 01 01 83 f8 41 7c 90 01 01 0f be 45 08 eb 90 01 01 c3 90 00 } //1
		$a_03_1 = {51 0f be 45 90 01 01 66 3b e4 74 90 01 01 83 f8 30 7c 90 01 01 0f be 45 90 01 01 66 3b c0 74 90 01 01 83 f8 66 7e 90 01 01 0f be 45 90 01 01 eb 90 01 01 83 f8 61 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}