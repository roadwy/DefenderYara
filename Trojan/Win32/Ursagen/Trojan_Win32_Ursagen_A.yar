
rule Trojan_Win32_Ursagen_A{
	meta:
		description = "Trojan:Win32/Ursagen.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 ff 15 90 01 04 8d 45 d0 50 6a 00 8d 8d 78 ff ff ff 51 6a 00 ff 15 90 01 04 6a 00 8d 95 50 f1 ff ff 52 6a 00 6a 00 6a 00 ff 15 90 01 04 6a 00 6a 00 ff 15 90 01 04 8d 45 b8 50 6a 00 ff 15 90 01 04 6a 00 6a 00 6a 00 8d 4d c4 51 6a 00 ff 15 90 00 } //01 00 
		$a_02_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 8d 4d f3 51 ff 15 90 01 04 68 44 d1 43 00 68 a0 f2 4b 00 e8 58 20 00 00 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}