
rule Trojan_Win32_Danmec_L{
	meta:
		description = "Trojan:Win32/Danmec.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 ea 01 8b 85 90 01 02 ff ff 88 94 05 90 01 02 ff ff e9 90 01 02 ff ff 90 09 14 00 8b 8d 90 01 02 ff ff 0f be 94 0d 90 01 02 ff ff 2b 95 90 01 02 ff ff 90 00 } //01 00 
		$a_03_1 = {33 c0 89 45 fc 0f 00 45 fc 33 c9 39 45 fc 0f 95 c1 8b c1 8b e5 5d c3 90 02 07 8b 08 8b 11 81 c2 00 00 00 40 56 89 15 90 01 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}