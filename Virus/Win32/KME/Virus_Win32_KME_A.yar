
rule Virus_Win32_KME_A{
	meta:
		description = "Virus:Win32/KME.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {0d 00 20 20 20 f7 d8 3d d2 9a 87 9a c3 } //1
		$a_01_1 = {ba 89 88 00 00 cd 20 96 00 01 00 c3 81 fa 89 88 00 00 } //1
		$a_00_2 = {5c 72 75 6e 64 6c 6c 31 36 2e 65 78 65 } //1 \rundll16.exe
		$a_01_3 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 } //1 RegisterServiceProcess
		$a_01_4 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //1 RegSetValueExA
		$a_00_5 = {3f 3a 5c 00 2a 2e 2a 00 2e 2e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}