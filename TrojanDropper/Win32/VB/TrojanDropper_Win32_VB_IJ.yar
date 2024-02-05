
rule TrojanDropper_Win32_VB_IJ{
	meta:
		description = "TrojanDropper:Win32/VB.IJ,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {43 00 4f 00 50 00 59 00 20 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 77 00 65 00 62 00 5c 00 70 00 72 00 69 00 6e 00 74 00 65 00 72 00 73 00 5c 00 33 00 36 00 30 00 73 00 2e 00 74 00 78 00 74 00 2f 00 62 00 2b 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 77 00 65 00 62 00 5c 00 70 00 72 00 69 00 6e 00 74 00 65 00 72 00 73 00 5c 00 6d 00 64 00 35 00 2e 00 74 00 78 00 74 00 2f 00 61 00 20 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 77 00 65 00 62 00 5c 00 70 00 72 00 69 00 6e 00 74 00 65 00 72 00 73 00 5c 00 33 00 36 00 30 00 73 00 70 00 2e 00 74 00 78 00 74 00 } //02 00 
		$a_01_1 = {66 00 6f 00 72 00 20 00 25 00 25 00 69 00 20 00 69 00 6e 00 20 00 28 00 63 00 20 00 64 00 20 00 65 00 20 00 66 00 20 00 67 00 20 00 68 00 29 00 20 00 64 00 6f 00 20 00 28 00 20 00 64 00 65 00 6c 00 20 00 2f 00 73 00 20 00 2f 00 66 00 20 00 2f 00 71 00 20 00 2f 00 61 00 20 00 25 00 25 00 69 00 3a 00 5c 00 2a 00 2e 00 6d 00 61 00 78 00 29 00 } //03 00 
		$a_01_2 = {64 00 69 00 72 00 20 00 63 00 3a 00 5c 00 20 00 3e 00 63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 77 00 65 00 62 00 5c 00 70 00 72 00 69 00 6e 00 74 00 65 00 72 00 73 00 5c 00 6d 00 64 00 35 00 2e 00 74 00 78 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}