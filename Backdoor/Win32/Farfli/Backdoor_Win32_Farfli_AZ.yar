
rule Backdoor_Win32_Farfli_AZ{
	meta:
		description = "Backdoor:Win32/Farfli.AZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_41_0 = {44 24 4d 5c c6 44 24 4e 2e c6 44 24 4f 5c c6 44 24 50 6b c6 44 24 51 69 88 5c 24 52 88 5c 24 53 c6 44 24 54 6d c6 44 24 55 64 c6 44 24 56 78 c6 44 24 57 00 01 } //00 16 
		$a_c6_1 = {e0 53 88 4d e1 c6 45 e3 45 c6 45 e4 76 88 4d e5 c6 45 e6 6e 01 00 0f 01 6c 6c 61 2f 34 2e 30 20 28 54 4f 4b 45 5a 29 00 00 5d 04 00 00 8f 09 03 80 5c 23 00 00 90 09 03 80 00 00 01 00 03 00 0d 00 } //a0 21 
	condition:
		any of ($a_*)
 
}