
rule Trojan_Win32_Picrosia_B{
	meta:
		description = "Trojan:Win32/Picrosia.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 83 e8 20 0f b7 d7 8b ca 33 d2 f7 f1 66 f7 ef 66 05 ef 00 66 25 00 ff 66 83 c0 30 66 89 43 ea 83 c3 20 4e 0f 85 2d ff ff ff } //01 00 
		$a_01_1 = {5b 00 20 00 54 00 61 00 62 00 20 00 5d 00 } //01 00  [ Tab ]
		$a_01_2 = {5b 00 42 00 41 00 43 00 4b 00 53 00 50 00 41 00 43 00 45 00 5d 00 } //01 00  [BACKSPACE]
		$a_01_3 = {5c 00 52 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 5c 00 62 00 69 00 6e 00 5c 00 73 00 79 00 73 00 5c 00 } //01 00  \Recovery\bin\sys\
		$a_01_4 = {45 00 78 00 73 00 69 00 73 00 74 00 20 00 3a 00 3a 00 3a 00 3a 00 } //00 00  Exsist ::::
		$a_00_5 = {5d 04 00 } //00 df 
	condition:
		any of ($a_*)
 
}