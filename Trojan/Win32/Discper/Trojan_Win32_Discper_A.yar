
rule Trojan_Win32_Discper_A{
	meta:
		description = "Trojan:Win32/Discper.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_81_0 = {2d 75 20 34 35 34 48 44 4c 44 74 71 43 4c 53 } //01 00 
		$a_81_1 = {2d 61 20 63 72 79 70 74 6f 6e 69 67 68 74 20 2d 6f 20 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f } //01 00 
		$a_81_2 = {6e 65 74 2e 65 78 65 00 61 63 63 6f 75 6e 74 73 20 2f 6d 61 78 70 77 61 67 65 3a 75 6e 6c 69 6d 69 74 65 64 00 } //01 00 
		$a_81_3 = {2f 66 20 2f 69 6d 20 63 6d 64 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}