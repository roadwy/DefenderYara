
rule Backdoor_Win32_Farfli_U{
	meta:
		description = "Backdoor:Win32/Farfli.U,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 50 56 57 ff 15 90 01 04 8b 4c 24 0c 33 c0 85 c9 76 0e 8a 14 30 80 f2 90 01 01 88 14 30 40 3b c1 72 f2 57 ff 15 90 00 } //01 00 
		$a_03_1 = {5c 75 73 65 72 2e 64 61 74 90 02 10 42 6c 6f 63 6b 49 6e 70 75 74 90 02 20 5c 63 6d 64 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}