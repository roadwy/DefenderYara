
rule Backdoor_Win32_Yonsole_A{
	meta:
		description = "Backdoor:Win32/Yonsole.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 05 08 00 00 77 ?? 74 ?? 8b c8 83 e9 02 74 ?? 81 e9 02 08 00 00 } //2
		$a_01_1 = {75 11 8b 45 10 8b 4d 1c 03 c1 89 84 24 } //1
		$a_03_2 = {7e 1f 8b 4c 24 04 8a 14 31 80 c2 ?? 88 14 31 8b 4c 24 04 8a 14 31 80 f2 ?? 88 14 31 46 3b f0 7c e1 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}