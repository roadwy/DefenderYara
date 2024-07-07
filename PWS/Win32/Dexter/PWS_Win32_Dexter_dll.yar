
rule PWS_Win32_Dexter_dll{
	meta:
		description = "PWS:Win32/Dexter!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 48 00 65 00 6c 00 70 00 65 00 72 00 53 00 6f 00 6c 00 75 00 74 00 69 00 6f 00 6e 00 73 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 } //1 Software\HelperSolutions Software
		$a_03_1 = {83 f9 72 75 25 c6 85 90 01 04 5b c6 85 90 01 04 63 c6 85 90 01 04 5d c6 85 90 01 04 00 c7 45 90 01 01 03 00 00 00 eb 12 90 00 } //1
		$a_00_2 = {8b 45 0c 0f be 08 33 d1 8b 45 08 88 10 8b 4d 0c 83 c1 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}