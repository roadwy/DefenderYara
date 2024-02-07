
rule PWS_Win32_Dozmot_F{
	meta:
		description = "PWS:Win32/Dozmot.F,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 5c 74 0b 3c 3a 74 07 83 ee 01 85 f6 7f ed } //01 00 
		$a_01_1 = {3d 64 6f 6d 6f } //01 00  =domo
		$a_01_2 = {2f 32 50 6f 73 74 4d 62 2e 61 73 70 } //01 00  /2PostMb.asp
		$a_01_3 = {31 36 33 2e 63 6f 6d } //01 00  163.com
		$a_01_4 = {33 36 30 53 45 2e 65 78 65 } //01 00  360SE.exe
		$a_00_5 = {77 6f 77 69 6e 66 6f 2e 69 6e 69 } //01 00  wowinfo.ini
		$a_00_6 = {77 6f 77 2e 65 78 65 } //01 00  wow.exe
		$a_01_7 = {53 65 63 75 72 69 74 79 4d 61 74 72 69 78 4b 65 79 70 61 64 42 75 74 74 6f 6e 4f 4b } //00 00  SecurityMatrixKeypadButtonOK
	condition:
		any of ($a_*)
 
}