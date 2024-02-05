
rule Worm_Win32_Duptwux_A{
	meta:
		description = "Worm:Win32/Duptwux.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 02 88 04 0f 47 83 c2 04 39 f2 7c ee 4b 85 db 7d e3 } //01 00 
		$a_03_1 = {3c 41 74 04 3c 61 75 0b 8d 90 01 03 ff ff e9 90 01 04 8d 90 01 03 ff ff e9 90 01 05 ff 15 90 01 04 83 f8 02 90 00 } //01 00 
		$a_03_2 = {80 3c 03 4d 75 90 01 01 80 7c 03 05 73 75 90 01 01 80 7c 03 08 74 75 90 01 01 80 7c 03 0c 6e 75 90 01 01 80 7c 03 0f 77 90 00 } //01 00 
		$a_03_3 = {80 3c 3e 4d 0f 85 90 01 04 80 7c 3e 05 73 0f 85 90 01 04 80 7c 3e 08 74 0f 85 90 01 04 80 7c 3e 0c 6e 0f 85 90 01 04 80 7c 3e 0f 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}