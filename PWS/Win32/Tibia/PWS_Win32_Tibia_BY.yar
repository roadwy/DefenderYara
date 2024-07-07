
rule PWS_Win32_Tibia_BY{
	meta:
		description = "PWS:Win32/Tibia.BY,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 03 00 00 "
		
	strings :
		$a_03_0 = {47 45 54 20 2f 75 90 01 02 2e 70 68 70 3f 64 61 74 61 3d 00 26 73 69 64 3d 00 20 48 54 54 50 2f 31 2e 31 0d 0a 00 48 6f 73 74 3a 20 77 77 77 2e 75 61 6e 65 73 6b 65 79 6c 6f 67 67 65 72 2e 70 6c 90 00 } //10
		$a_00_1 = {89 4c 24 10 c7 44 24 0c 01 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 07 00 00 00 c7 04 24 00 00 00 00 c7 85 a8 fd ff ff ff ff ff ff e8 } //3
		$a_00_2 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //3 \Windows\CurrentVersion\Run
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3) >=13
 
}