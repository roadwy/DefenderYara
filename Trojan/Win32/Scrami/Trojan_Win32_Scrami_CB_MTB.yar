
rule Trojan_Win32_Scrami_CB_MTB{
	meta:
		description = "Trojan:Win32/Scrami.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 72 6f 6b 2e 65 78 65 } //01 00  prok.exe
		$a_01_1 = {50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f } //01 00  ProcessStartInfo
		$a_01_2 = {50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 79 6c 65 } //01 00  ProcessWindowStyle
		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //01 00  powershell.exe
		$a_01_4 = {30 00 41 00 53 00 51 00 42 00 75 00 41 00 48 00 59 00 41 00 62 00 77 00 42 00 72 00 41 00 47 00 55 00 } //01 00  0ASQBuAHYAbwBrAGU
		$a_01_5 = {41 00 43 00 41 00 41 00 4c 00 51 00 42 00 56 00 41 00 48 00 49 00 41 00 61 00 51 00 41 00 } //00 00  ACAALQBVAHIAaQA
	condition:
		any of ($a_*)
 
}