
rule Worm_Win32_Fakefolder_B{
	meta:
		description = "Worm:Win32/Fakefolder.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 06 50 ff 15 90 01 04 8b 4c 24 90 01 01 6a 01 6a 00 51 68 90 01 04 68 90 01 04 6a 00 ff 15 90 00 } //1
		$a_00_1 = {72 65 67 65 64 69 74 2e 65 78 65 00 2d 73 20 } //1
		$a_00_2 = {00 70 6c 61 79 65 2e 6c 6f 67 00 } //1
		$a_00_3 = {00 57 69 6e 53 78 53 5c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}