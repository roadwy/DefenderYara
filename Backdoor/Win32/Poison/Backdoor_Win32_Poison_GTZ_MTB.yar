
rule Backdoor_Win32_Poison_GTZ_MTB{
	meta:
		description = "Backdoor:Win32/Poison.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {6d 31 00 0d ?? ?? ?? ?? 53 53 59 33 32 00 19 01 00 } //10
		$a_80_1 = {73 76 63 68 6f 63 74 2e 65 78 65 } //svchoct.exe  1
		$a_80_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 20 73 76 63 68 6f 63 74 } //taskkill /f /im  svchoct  1
		$a_80_3 = {6b 33 79 6c 6f 67 67 65 72 2e 74 78 74 } //k3ylogger.txt  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}