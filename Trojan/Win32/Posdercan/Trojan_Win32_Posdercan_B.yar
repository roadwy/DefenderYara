
rule Trojan_Win32_Posdercan_B{
	meta:
		description = "Trojan:Win32/Posdercan.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_00_1 = {70 00 77 00 73 00 68 00 2e 00 65 00 78 00 65 00 00 00 } //02 00 
		$a_00_2 = {72 00 61 00 77 00 2e 00 67 00 69 00 74 00 68 00 75 00 62 00 75 00 73 00 65 00 72 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //fb ff  raw.githubusercontent
		$a_00_3 = {73 00 79 00 73 00 6d 00 6f 00 6e 00 } //fb ff  sysmon
		$a_00_4 = {63 00 6f 00 6d 00 70 00 61 00 73 00 73 00 6d 00 73 00 70 00 } //fb ff  compassmsp
		$a_00_5 = {63 00 61 00 6c 00 74 00 65 00 63 00 } //00 00  caltec
	condition:
		any of ($a_*)
 
}