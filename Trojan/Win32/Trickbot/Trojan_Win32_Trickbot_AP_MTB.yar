
rule Trojan_Win32_Trickbot_AP_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {74 61 62 64 6c 6c 5f 78 38 36 2e 64 6c 6c } //1 tabdll_x86.dll
		$a_81_1 = {2e 6c 6f 63 6b 65 72 } //1 .locker
		$a_81_2 = {2e 78 74 61 62 } //1 .xtab
		$a_81_3 = {30 31 32 33 34 35 36 37 38 39 5f 71 77 65 72 74 79 75 69 6f 70 61 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e 6d } //1 0123456789_qwertyuiopasdfghjklzxcvbnm
		$a_81_4 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //1 ReflectiveLoader
		$a_81_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 } //1 CreateObject
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}