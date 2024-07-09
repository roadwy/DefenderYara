
rule Trojan_Win32_Fareit_SF_MTB{
	meta:
		description = "Trojan:Win32/Fareit.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 10 b1 f8 40 [0-06] 81 c1 31 90 90 48 00 [0-10] f7 c1 ef 37 b6 4a [0-15] 39 cb 75 } //1
		$a_03_1 = {66 3d 3a c6 39 da 83 eb 03 [0-06] 83 eb 01 [0-06] ff 34 1f [0-10] 8f 04 18 [0-06] 38 ff 31 34 18 [0-25] 3d e2 89 b8 4a 83 fb 00 7f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}