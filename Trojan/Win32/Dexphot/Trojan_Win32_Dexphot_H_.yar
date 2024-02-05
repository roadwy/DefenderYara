
rule Trojan_Win32_Dexphot_H_{
	meta:
		description = "Trojan:Win32/Dexphot.H!!Dexphot.H,SIGNATURE_TYPE_ARHSTR_EXT,0e 00 0e 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 e2 e1 a3 dd 66 89 04 24 9c 60 } //01 00 
		$a_00_1 = {68 f0 8f 5b 1e ff 34 24 e9 } //01 00 
		$a_00_2 = {68 f5 25 c2 2a 9c 52 68 2a 94 2d 48 8d 64 24 30 } //01 00 
		$a_02_3 = {60 9c 68 d6 6e 60 91 e9 90 01 04 e8 90 01 04 0f b6 c3 90 00 } //0a 00 
		$a_01_4 = {78 55 6e 7a 72 54 00 00 ff ff ff ff 02 00 00 00 63 47 00 00 ff ff ff ff 04 00 00 00 39 33 5a 58 00 00 00 00 ff ff ff ff 03 00 00 00 4a 7a 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}