
rule Trojan_Win32_CryptInject_AU_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 00 6e 00 74 00 65 00 72 00 66 00 61 00 63 00 65 00 5c 00 7b 00 62 00 31 00 39 00 36 00 62 00 32 00 38 00 37 00 2d 00 62 00 61 00 62 00 34 00 2d 00 31 00 30 00 31 00 61 00 2d 00 62 00 36 00 39 00 63 00 2d 00 30 00 30 00 61 00 61 00 30 00 30 00 33 00 34 00 31 00 64 00 30 00 37 00 7d 00 } //01 00  Interface\{b196b287-bab4-101a-b69c-00aa00341d07}
		$a_02_1 = {55 8b ec 83 ec 08 56 8b 15 90 01 04 ff 35 90 01 04 8f 45 f8 8b 75 f8 33 f2 8b d6 8b ca b8 90 01 04 03 c1 2d 90 01 04 89 45 fc a1 90 01 04 8b 4d fc 89 08 5e 8b e5 5d c3 90 00 } //01 00 
		$a_00_2 = {0f be 04 30 f7 d8 8b 4d f8 0f be 11 2b d0 8b 45 f8 88 10 5e 8b e5 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}