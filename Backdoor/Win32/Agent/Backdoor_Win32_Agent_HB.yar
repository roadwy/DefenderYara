
rule Backdoor_Win32_Agent_HB{
	meta:
		description = "Backdoor:Win32/Agent.HB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 f2 62 88 14 01 41 81 f9 ?? ?? 00 00 76 ee } //1
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 67 68 30 73 74 } //1 SOFTWARE\Microsoft\gh0st
		$a_00_2 = {43 6f 6d 72 65 73 2e 64 6c 6c } //1 Comres.dll
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}