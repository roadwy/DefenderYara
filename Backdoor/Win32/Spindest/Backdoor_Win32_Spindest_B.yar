
rule Backdoor_Win32_Spindest_B{
	meta:
		description = "Backdoor:Win32/Spindest.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 08 80 f3 41 88 1c 08 40 3b c2 7c f2 } //1
		$a_03_1 = {8d 45 01 51 c7 44 24 ?? 4d 53 55 00 89 5c 24 ?? 52 c7 06 12 00 00 00 89 46 04 } //1
		$a_01_2 = {2f 25 6c 64 6e 2e 74 78 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}