
rule Trojan_Win32_Gasti_BT_MTB{
	meta:
		description = "Trojan:Win32/Gasti.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 04 00 "
		
	strings :
		$a_01_0 = {6d 2e 6d 73 73 71 6c 6e 65 77 70 72 6f 2e 63 6f 6d 2f 6d 73 73 71 6c 38 38 2f 75 70 6c 6f 61 64 2e 70 68 70 } //04 00 
		$a_01_1 = {72 72 72 2e 74 78 74 } //02 00 
		$a_01_2 = {57 65 62 4b 69 74 46 6f 72 6d 42 6f 75 6e 64 61 72 79 38 32 58 42 34 75 39 59 77 67 30 41 36 7a 55 6d } //01 00 
		$a_01_3 = {5b 74 6f 74 61 6c 5f 62 6c 6f 62 5f 6e 75 6d 5d } //01 00 
		$a_01_4 = {5b 68 61 73 68 43 6f 64 65 5d } //00 00 
	condition:
		any of ($a_*)
 
}