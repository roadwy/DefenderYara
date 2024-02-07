
rule Trojan_Win32_Emotetcrypt_GX_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 14 2a 03 c2 99 bd 90 01 04 f7 fd 8d 04 3e 0f af c1 03 c0 8b e8 8b c3 0f af c6 8b f0 a1 90 01 04 0f af f0 2b f5 03 54 24 90 01 01 2b c8 8b 44 24 90 01 01 0f af 05 90 01 04 2b f7 83 ee 90 01 01 0f af f3 8d 04 40 8d 0c 4e 2b c8 8b 44 24 90 01 01 2b cf 8a 0c 4a 30 08 90 00 } //01 00 
		$a_81_1 = {72 5f 78 61 76 24 6e 61 32 4c 29 46 4f 65 54 31 23 71 44 33 53 57 52 23 44 4f 51 42 7a 40 68 3f 26 2b 68 79 4a 25 43 62 59 2a 6a 31 7a 25 6b 28 6b 53 77 55 58 24 45 4c 44 49 78 77 66 75 68 62 79 44 49 65 } //00 00  r_xav$na2L)FOeT1#qD3SWR#DOQBz@h?&+hyJ%CbY*j1z%k(kSwUX$ELDIxwfuhbyDIe
	condition:
		any of ($a_*)
 
}