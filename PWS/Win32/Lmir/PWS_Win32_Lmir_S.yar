
rule PWS_Win32_Lmir_S{
	meta:
		description = "PWS:Win32/Lmir.S,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {51 51 4c 6f c7 45 ?? 67 69 6e 2e c7 45 ?? 65 78 65 00 } //1
		$a_03_1 = {25 73 3f 61 c7 45 ?? 3d 34 26 75 c7 45 ?? 3d 25 73 26 } //1
		$a_03_2 = {45 78 65 63 c7 45 ?? 75 74 65 48 c7 45 ?? 6f 6f 6b 73 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}