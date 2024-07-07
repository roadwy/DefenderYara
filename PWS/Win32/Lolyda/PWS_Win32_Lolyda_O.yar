
rule PWS_Win32_Lolyda_O{
	meta:
		description = "PWS:Win32/Lolyda.O,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {60 9c ff b6 24 1a 00 00 8f 05 90 01 04 e8 90 01 04 c7 05 90 01 04 01 00 00 00 9d 61 90 90 90 00 } //1
		$a_01_1 = {80 7e 01 31 72 06 80 7e 01 38 76 02 eb 58 80 7e 02 41 72 06 80 7e 02 4a 76 02 eb 4a } //1
		$a_00_2 = {61 63 63 6f 75 6e 74 3d 25 73 26 73 65 72 76 65 72 3d 25 73 26 70 73 77 69 6d 61 67 65 63 6f 75 6e 74 3d 25 64 26 70 73 77 69 6d 61 67 65 69 6e 64 65 78 3d 25 64 26 70 73 77 69 6d 61 67 65 64 61 } //1 account=%s&server=%s&pswimagecount=%d&pswimageindex=%d&pswimageda
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}