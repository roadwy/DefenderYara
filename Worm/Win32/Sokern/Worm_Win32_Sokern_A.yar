
rule Worm_Win32_Sokern_A{
	meta:
		description = "Worm:Win32/Sokern.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 2d 53 65 63 75 72 65 20 47 61 74 65 6b 65 65 70 65 72 20 48 61 6e 64 6c 65 72 20 53 74 61 72 74 65 72 } //01 00  F-Secure Gatekeeper Handler Starter
		$a_01_1 = {4a 00 43 00 5c 00 6e 00 74 00 73 00 6f 00 6b 00 72 00 6e 00 6c 00 2e 00 76 00 62 00 70 00 } //01 00  JC\ntsokrnl.vbp
		$a_01_2 = {5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  \SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {4b 00 3a 00 5c 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //00 00  K:\Autorun.inf
	condition:
		any of ($a_*)
 
}