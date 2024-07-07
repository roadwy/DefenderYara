
rule Backdoor_Win32_Simda_gen_C{
	meta:
		description = "Backdoor:Win32/Simda.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 25 65 76 69 72 44 6c 61 63 69 73 79 68 50 5c 2e 5c 5c } //1 d%evirDlacisyhP\.\\
		$a_01_1 = {68 73 61 68 3d 72 65 6c 6c 6f 72 74 6e 6f 63 3f 2f } //1 hsah=rellortnoc?/
		$a_01_2 = {3d 72 65 6c 6c 6f 72 74 6e 6f 63 26 73 25 3d 6c 74 74 26 64 25 3d 64 69 75 26 65 74 61 64 70 75 3d 65 70 79 54 70 75 74 65 73 26 } //1 =rellortnoc&s%=ltt&d%=diu&etadpu=epyTputes&
		$a_01_3 = {8b 75 08 74 15 32 06 0f b6 d0 c1 e8 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}