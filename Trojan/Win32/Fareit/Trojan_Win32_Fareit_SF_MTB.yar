
rule Trojan_Win32_Fareit_SF_MTB{
	meta:
		description = "Trojan:Win32/Fareit.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 10 b1 f8 40 90 02 06 81 c1 31 90 90 48 00 90 02 10 f7 c1 ef 37 b6 4a 90 02 15 39 cb 75 90 00 } //01 00 
		$a_03_1 = {66 3d 3a c6 39 da 83 eb 03 90 02 06 83 eb 01 90 02 06 ff 34 1f 90 02 10 8f 04 18 90 02 06 38 ff 31 34 18 90 02 25 3d e2 89 b8 4a 83 fb 00 7f 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}