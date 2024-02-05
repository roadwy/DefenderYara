
rule Trojan_Win32_Filecoderkrypt_SG_MTB{
	meta:
		description = "Trojan:Win32/Filecoderkrypt.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 f6 ff d7 81 fe 90 01 04 7f 12 46 8b c6 99 83 fa 01 7c ed 7f 07 3d 90 01 04 72 e4 90 00 } //01 00 
		$a_03_1 = {55 8b ec 57 bf 90 01 04 57 ff 15 90 01 04 ff 75 08 ff 15 90 01 04 81 c7 90 01 04 81 ff 90 01 04 77 04 85 c0 74 de 5f 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}