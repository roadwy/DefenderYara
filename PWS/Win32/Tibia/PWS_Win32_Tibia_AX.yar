
rule PWS_Win32_Tibia_AX{
	meta:
		description = "PWS:Win32/Tibia.AX,SIGNATURE_TYPE_PEHSTR_EXT,08 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_02_0 = {be 1e 00 00 00 8d 45 90 01 01 50 56 8d 85 90 01 04 50 68 e4 d3 77 00 53 e8 90 00 } //01 00 
		$a_01_1 = {74 69 62 69 61 43 6c 69 65 6e 74 } //01 00  tibiaClient
		$a_01_2 = {73 6d 74 70 2e 73 65 72 77 65 72 2e 70 6c } //03 00  smtp.serwer.pl
		$a_01_3 = {6b 65 79 6c 6f 67 67 65 72 76 73 6b 33 } //01 00  keyloggervsk3
		$a_01_4 = {49 64 53 4d 54 50 31 43 6f 6e 6e 65 63 74 65 64 } //00 00  IdSMTP1Connected
	condition:
		any of ($a_*)
 
}