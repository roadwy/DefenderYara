
rule Trojan_Win32_FormBook_MBKE_MTB{
	meta:
		description = "Trojan:Win32/FormBook.MBKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 49 8b 55 f8 8a 82 90 01 04 88 45 ff 8b 4d e4 03 4d f4 8a 11 88 55 fe 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 0f b6 55 fe 33 c2 8b 4d f8 88 81 90 01 04 8b 45 f4 83 c0 01 99 b9 90 01 04 f7 f9 89 55 f4 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}