
rule PWS_Win32_Frethog_MO{
	meta:
		description = "PWS:Win32/Frethog.MO,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 44 4c 4c 2e 64 6c 6c 00 48 6f 6f 6b 6f 66 66 00 48 6f 6f 6b 6f 6e 00 00 } //05 00 
		$a_01_1 = {65 6c 65 6d 65 6e 74 63 6c 69 65 6e 74 2e 65 78 65 } //01 00  elementclient.exe
		$a_01_2 = {61 63 74 69 6f 6e 3d 75 70 26 7a 74 3d } //01 00  action=up&zt=
		$a_01_3 = {69 73 6f 6e 6c 69 6e 65 00 } //01 00 
		$a_01_4 = {6e 6f 72 65 73 70 6f 6e 64 00 } //01 00  潮敲灳湯d
		$a_01_5 = {2f 66 6c 61 73 68 2e 61 73 70 } //00 00  /flash.asp
	condition:
		any of ($a_*)
 
}