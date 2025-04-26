
rule Backdoor_Win32_Zegost_BL{
	meta:
		description = "Backdoor:Win32/Zegost.BL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {6a 02 6a 00 68 00 fc ff ff ?? ff 15 } //1
		$a_02_1 = {8a 1c 16 3a 1c 2a 75 ?? 42 3b d1 7c } //1
		$a_01_2 = {00 50 50 50 50 50 50 00 } //1 倀偐偐P
		$a_00_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 68 69 } //1 rundll32.exe %s,hi
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}