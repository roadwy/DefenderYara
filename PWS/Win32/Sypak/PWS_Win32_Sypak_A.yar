
rule PWS_Win32_Sypak_A{
	meta:
		description = "PWS:Win32/Sypak.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 47 65 74 53 6b 79 70 65 41 70 70 44 61 74 61 44 69 72 } //01 00  .GetSkypeAppDataDir
		$a_00_1 = {53 00 6b 00 79 00 70 00 65 00 5c 00 41 00 70 00 70 00 73 00 5c 00 6c 00 6f 00 67 00 69 00 6e 00 5c 00 69 00 6e 00 64 00 65 00 78 00 2e 00 68 00 74 00 6d 00 6c 00 } //01 00  Skype\Apps\login\index.html
		$a_00_2 = {50 72 6f 6a 65 63 74 73 5c 53 46 6c 6f 6f 64 65 72 5c } //02 00  Projects\SFlooder\
		$a_03_3 = {50 8b 45 08 50 ff 15 90 01 04 8b f8 8b c6 8d 50 01 8d 49 00 8a 08 40 84 c9 75 f9 2b c2 50 6a 00 56 e8 90 01 04 83 c4 0c 8b c7 90 00 } //02 00 
		$a_03_4 = {50 6a 01 53 6a 26 53 ff 15 90 01 04 8d bd 90 01 01 fe ff ff 4f 8d 9b 00 00 00 00 8a 47 01 47 3a c3 75 f8 b9 05 00 00 00 be 90 01 04 f3 a5 68 03 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}