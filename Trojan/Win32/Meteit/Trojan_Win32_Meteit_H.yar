
rule Trojan_Win32_Meteit_H{
	meta:
		description = "Trojan:Win32/Meteit.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 e8 34 39 45 8c 75 54 8b 45 b0 03 45 90 0f b6 48 20 8b 45 90 83 c0 20 8b 55 b0 0f b6 b2 80 01 00 00 83 c6 04 33 d2 f7 f6 0f b6 c2 } //01 00 
		$a_01_1 = {0b ca 8b 55 b4 0f b6 52 2c f7 d2 8b 75 b4 0f b6 76 2c 0b d6 23 ca 23 c1 83 f8 62 0f 85 c9 04 00 00 } //01 00 
		$a_01_2 = {f7 d0 0b f0 23 ce 88 4d f5 8b 45 b0 03 85 d4 fe ff ff 8a 4d f5 88 88 d8 13 00 00 e9 21 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}