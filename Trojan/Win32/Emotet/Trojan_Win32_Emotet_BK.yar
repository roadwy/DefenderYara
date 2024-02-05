
rule Trojan_Win32_Emotet_BK{
	meta:
		description = "Trojan:Win32/Emotet.BK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 d7 8d b4 0a 51 ff ff ff 81 fe 23 0b 00 00 72 0c 8d 44 0a 05 c7 44 24 1c 00 00 00 00 33 ed 8d 71 e4 2b f0 1b 6c 24 1c 03 d3 81 fa b5 00 00 00 89 35 08 90 42 00 89 2d 0c 90 42 00 75 0f 8b 15 04 90 42 00 2b d0 8d 54 51 f4 0f b7 fa 0f b7 d7 03 d2 8d b2 51 ff ff ff 81 fe 23 0b 00 00 7c 08 8d 42 05 99 89 54 24 1c 0f af cf 8b 54 24 10 8b 1a 03 c8 0f b7 f9 8b 4c 24 20 01 0d 10 90 42 00 } //01 00 
		$a_01_1 = {0f b7 f7 b9 00 00 00 00 11 0d 14 90 42 00 8b ce 2b 0d 04 90 42 00 83 c1 0f 8d ac 0e 51 ff ff ff 81 fd 23 0b 00 00 72 14 8d 74 0e 05 89 35 08 90 42 00 c7 05 0c 90 42 00 00 00 00 00 8b f1 0f af f7 8d 74 06 01 0f af f1 0f b7 fe 0f b7 f7 81 c3 c0 9b de 01 8d ac 0e 51 ff ff ff 81 fd 23 0b 00 00 89 1a 72 14 8d 6c 0e 05 89 2d 08 90 42 00 c7 05 0c 90 42 00 00 00 00 00 0f af 35 10 90 42 00 6b f6 f3 83 c2 04 03 ce 83 6c 24 14 01 89 54 24 10 0f 85 e8 fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}