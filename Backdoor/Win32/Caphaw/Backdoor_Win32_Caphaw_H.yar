
rule Backdoor_Win32_Caphaw_H{
	meta:
		description = "Backdoor:Win32/Caphaw.H,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {26 6e 65 74 3d 25 73 26 63 6d 64 3d 6c 6f 67 26 77 3d 63 6d 70 69 6e 66 6f 26 62 74 3d 25 73 26 76 65 72 3d } //3 &net=%s&cmd=log&w=cmpinfo&bt=%s&ver=
		$a_01_1 = {2f 70 69 6e 67 2e 68 74 6d 6c 00 } //1
		$a_01_2 = {7c 7c 42 6f 74 6e 65 74 3d } //1 ||Botnet=
		$a_01_3 = {7c 7c 48 4a 50 61 74 68 3d } //1 ||HJPath=
		$a_01_4 = {41 56 46 46 5f 48 6f 6f 6b } //1 AVFF_Hook
		$a_01_5 = {41 56 49 45 5f 48 6f 6f 6b } //1 AVIE_Hook
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}