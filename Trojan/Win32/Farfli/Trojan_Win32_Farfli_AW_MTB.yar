
rule Trojan_Win32_Farfli_AW_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AW!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8a 14 01 8b da 81 e3 ff 00 00 00 03 f3 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8a 1c 06 88 54 24 18 88 1c 01 8b 5c 24 18 88 14 06 33 d2 8a 14 01 81 e3 ff 00 00 00 03 d3 81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72 90 } //01 00 
		$a_01_1 = {8a 14 08 8b 2f 8b da 81 e3 ff 00 00 00 03 dd 03 f3 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8a 1c 0e 83 c7 04 88 1c 08 40 3d 00 01 00 00 88 14 0e 7c cb } //01 00 
		$a_01_2 = {8b 0b 8b 73 04 8b 7c 24 18 8b d1 03 f7 8b f8 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 89 43 f8 8b 4c 24 20 8b 44 24 10 40 83 c3 28 8b 11 33 c9 89 44 24 10 66 8b 4a 06 3b c1 0f 8c } //00 00 
	condition:
		any of ($a_*)
 
}