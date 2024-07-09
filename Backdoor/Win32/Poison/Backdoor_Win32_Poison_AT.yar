
rule Backdoor_Win32_Poison_AT{
	meta:
		description = "Backdoor:Win32/Poison.AT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {99 b9 1a 00 00 00 f7 f9 83 c2 61 } //1
		$a_02_1 = {66 c7 44 24 ?? 40 00 c6 44 24 ?? 80 c6 44 24 ?? 06 c6 44 24 ?? 50 } //1
		$a_00_2 = {99 b9 fa 00 00 00 f7 f9 42 } //1
		$a_00_3 = {4d 44 20 53 65 72 76 69 63 65 73 42 } //1 MD ServicesB
		$a_00_4 = {53 76 63 25 63 25 63 25 63 25 63 2e 65 78 65 } //1 Svc%c%c%c%c.exe
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}