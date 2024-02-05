
rule Trojan_Win32_Fareit_MM_MTB{
	meta:
		description = "Trojan:Win32/Fareit.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {76 05 e8 6d 3d f9 ff 8b 84 85 e4 fb ff ff 33 d2 8a 55 f7 33 c2 3d ff 00 00 00 76 05 e8 53 3d f9 ff 8b 55 e8 88 90 01 02 47 ff 4d e4 0f 85 94 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}