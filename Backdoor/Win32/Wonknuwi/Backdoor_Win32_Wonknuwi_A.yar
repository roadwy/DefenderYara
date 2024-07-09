
rule Backdoor_Win32_Wonknuwi_A{
	meta:
		description = "Backdoor:Win32/Wonknuwi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 1e 8b fb 8a 82 ?? ?? ?? ?? 32 c8 33 c0 88 0c 1e 83 c9 ff 46 f2 ae f7 d1 49 3b f1 72 d7 } //1
		$a_03_1 = {8d 8c 24 60 01 00 00 68 b4 00 00 00 51 52 e8 ?? ?? ?? ?? 8b e8 3b eb 74 05 83 fd ff 75 5a } //1
		$a_01_2 = {55 6e 6b 6e 6f 77 00 00 57 69 6e 64 6f 77 73 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}