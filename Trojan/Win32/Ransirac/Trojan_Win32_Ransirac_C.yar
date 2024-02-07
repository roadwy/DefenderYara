
rule Trojan_Win32_Ransirac_C{
	meta:
		description = "Trojan:Win32/Ransirac.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 61 6c 75 70 61 2f 3f 69 64 3d } //01 00  zalupa/?id=
		$a_01_1 = {6a 64 6a 03 51 ff d7 8b 56 20 6a 00 6a 01 6a 06 52 ff d7 68 88 13 00 00 ff d3 6a 00 } //01 00 
		$a_01_2 = {7b 36 45 39 36 37 35 46 39 2d 43 37 43 34 2d 34 34 38 65 2d 38 30 46 36 2d 43 44 46 32 35 34 34 38 43 34 37 45 7d } //01 00  {6E9675F9-C7C4-448e-80F6-CDF25448C47E}
		$a_01_3 = {49 6e 65 74 41 63 63 65 6c 65 72 61 74 6f 72 } //01 00  InetAccelerator
		$a_01_4 = {37 68 36 6b 68 39 6c 38 } //00 00  7h6kh9l8
	condition:
		any of ($a_*)
 
}