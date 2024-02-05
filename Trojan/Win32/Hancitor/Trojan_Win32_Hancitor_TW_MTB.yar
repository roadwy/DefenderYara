
rule Trojan_Win32_Hancitor_TW_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.TW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 75 f4 81 c6 90 01 04 8b 5d f4 81 c3 90 01 04 c7 04 24 90 01 04 e8 90 01 02 00 00 89 c2 8b 45 f4 89 d1 ba 00 00 00 00 f7 f1 0f b6 92 90 01 04 0f b6 03 28 d0 88 06 8d 45 f4 ff 00 eb ae b8 90 01 04 83 c4 10 5b 5e 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}