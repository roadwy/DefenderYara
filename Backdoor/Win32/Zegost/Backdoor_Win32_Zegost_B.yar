
rule Backdoor_Win32_Zegost_B{
	meta:
		description = "Backdoor:Win32/Zegost.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 00 02 00 00 72 ?? 3d 08 02 00 00 77 ?? 8b ?? 04 [0-10] c1 ?? 10 } //2
		$a_03_1 = {83 fe 01 0f 82 ?? ?? ?? ?? 81 fe 80 00 00 00 0f 87 } //1
		$a_01_2 = {47 68 30 73 74 } //1 Gh0st
		$a_03_3 = {83 c2 0d 52 ff d0 a1 ?? ?? ?? ?? 83 c0 0d 50 ff 15 ?? ?? ?? ?? 83 f8 ff 5f 74 0c 8b 0d ?? ?? ?? ?? c6 41 0c 01 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}