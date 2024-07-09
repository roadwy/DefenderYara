
rule Backdoor_Win32_Argech_A{
	meta:
		description = "Backdoor:Win32/Argech.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {b8 89 88 88 88 f7 25 ?? ?? ?? ?? c1 ea 05 b8 d3 4d 62 10 f7 e2 } //1
		$a_01_1 = {6a 00 6a 68 55 51 ff 15 } //1
		$a_01_2 = {e9 7f 02 00 00 3c 01 0f 85 72 02 00 00 6a 5c 8d 44 24 24 } //2
		$a_03_3 = {79 08 4a 81 ca 00 ff ff ff 42 83 c0 ?? 3d ?? ?? ?? ?? 0f 82 ?? ?? ff ff 6a 00 8d 44 24 14 50 68 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2) >=2
 
}