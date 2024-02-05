
rule PWS_Win32_Lolyda_AX{
	meta:
		description = "PWS:Win32/Lolyda.AX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 2c 50 ff 15 90 01 04 83 c4 08 40 6a 00 50 6a 00 6a 00 e8 90 00 } //01 00 
		$a_03_1 = {b8 00 20 00 00 2b c3 6a 00 8d 0c 2b 50 51 52 ff 15 90 01 04 85 c0 7e 45 90 00 } //01 00 
		$a_01_2 = {42 4e 50 53 44 6c 6c 2e 64 6c 6c 00 43 6f 47 65 74 43 6f 6d 43 61 74 61 6c 6f 67 00 73 72 70 63 73 73 2e 43 6f 47 65 74 43 6f 6d 43 61 74 61 6c 6f 67 00 47 65 74 52 50 43 53 53 49 6e 66 6f 00 } //01 00 
		$a_01_3 = {25 73 7e 25 30 36 78 2e 7e 7e 7e } //00 00 
	condition:
		any of ($a_*)
 
}