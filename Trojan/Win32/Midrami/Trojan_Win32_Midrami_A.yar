
rule Trojan_Win32_Midrami_A{
	meta:
		description = "Trojan:Win32/Midrami.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {6e 65 6c 33 c7 05 90 01 03 00 32 2e 64 6c 66 c7 05 90 01 03 00 65 72 66 c7 05 90 01 03 00 6c 00 c6 05 90 00 } //01 00 
		$a_02_1 = {00 6c 65 33 32 c7 05 90 01 03 00 4d 6f 64 75 c7 05 90 01 03 00 72 73 74 57 66 c7 05 90 01 03 00 46 69 90 00 } //01 00 
		$a_02_2 = {72 74 75 61 c7 05 90 01 04 74 65 63 74 c7 05 90 01 04 6c 50 72 6f 66 c7 05 90 01 04 56 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}