
rule Trojan_Win32_Tracur_BI{
	meta:
		description = "Trojan:Win32/Tracur.BI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {71 6b 77 3d 00 } //1
		$a_01_1 = {6d 3d 25 73 26 7a 3d 25 73 } //1 m=%s&z=%s
		$a_03_2 = {8a 4c 16 01 32 8b ?? ?? ?? ?? 88 0c 10 42 43 3b d7 72 e6 } //1
		$a_01_3 = {8b 5d f8 80 3c 1f 6b 75 36 80 7c 1f 01 31 75 2f 80 7c 1f 02 20 75 28 80 7c 1f 03 3d 75 21 80 7c 1f 04 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}