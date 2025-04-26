
rule Backdoor_Win32_Bifrose_gen_E{
	meta:
		description = "Backdoor:Win32/Bifrose.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 31 d2 8d 0c 07 89 f8 f7 75 14 8b 45 10 8a 04 02 25 ff 00 00 00 31 01 47 3b 7d 0c 7c e0 } //1
		$a_03_1 = {6a 04 50 57 ff d6 81 75 ?? 68 a7 62 4d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}