
rule Backdoor_Win32_GoldenLight_B{
	meta:
		description = "Backdoor:Win32/GoldenLight.B,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 23 f1 de bc ff 15 ?? ?? ?? ?? 8b 74 24 ?? 83 c9 ff 8b fe 33 c0 83 c4 04 33 db f2 ae f7 d1 49 74 2a 55 8b 2d ?? ?? ?? ?? ff d5 8a 0c 33 8b fe c1 f8 0c 32 c1 83 c9 ff 32 c3 34 a9 88 04 33 33 c0 43 f2 ae f7 d1 49 3b d9 72 de } //4
		$a_01_1 = {8a 04 0e 8a d3 32 01 f6 d2 32 c2 88 01 75 02 88 11 43 41 83 fb 1c 7c e8 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*4) >=100
 
}