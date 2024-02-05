
rule TrojanProxy_Win32_Banker_BM{
	meta:
		description = "TrojanProxy:Win32/Banker.BM,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 61 75 74 6f 63 6f 6e 66 69 67 5f 75 72 6c 22 2c } //02 00 
		$a_00_1 = {73 61 6e 6f 61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 75 73 65 72 6e 61 6d 65 70 61 73 73 77 6f 72 64 07 69 64 73 6f 63 6b 73 } //01 00 
		$a_00_2 = {2e 63 6f 6d 2e 62 72 } //02 00 
		$a_00_3 = {3f 6e 6f 6d 65 70 63 3d } //02 00 
		$a_00_4 = {3b 70 69 63 61 73 2b 2b 29 } //00 00 
	condition:
		any of ($a_*)
 
}