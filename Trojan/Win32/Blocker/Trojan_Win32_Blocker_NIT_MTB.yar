
rule Trojan_Win32_Blocker_NIT_MTB{
	meta:
		description = "Trojan:Win32/Blocker.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 bd 80 fe ff ff ff 15 20 e0 40 00 8b f0 56 57 ff 15 38 e0 40 00 56 ff b5 80 fe ff ff 8b f8 ff 15 3c e0 40 00 57 89 85 80 fe ff ff ff 15 14 e0 40 00 8b bd 80 fe ff ff 8b f0 57 e8 07 23 00 00 83 c4 04 89 85 7c fe ff ff 85 ff 74 14 8b c8 2b f0 8b d7 8a 04 0e 8d 49 01 88 41 ff 83 ea 01 75 f2 66 a1 90 2b 41 00 0f 10 05 78 2b 41 00 66 89 85 e8 fe ff ff 8d 85 f8 fe ff ff 68 00 01 00 00 0f 11 85 d0 fe ff ff 50 f3 0f 7e 05 88 2b 41 00 68 94 2b 41 00 } //2
		$a_01_1 = {8b ca 83 e1 03 68 08 2b 41 00 f3 a4 68 01 00 00 80 ff 15 04 e0 40 00 85 c0 75 49 8d 8d f8 fe ff ff 8d 51 02 0f 1f 44 00 00 66 8b 01 83 c1 02 66 85 c0 75 f5 2b ca d1 f9 8d 04 09 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}