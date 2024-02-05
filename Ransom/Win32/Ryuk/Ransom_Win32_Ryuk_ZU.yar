
rule Ransom_Win32_Ryuk_ZU{
	meta:
		description = "Ransom:Win32/Ryuk.ZU,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_01_1 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc 5a 7d 45 33 c9 8b 55 fc c1 e2 05 03 55 08 89 0a 89 4a 04 89 4a 08 89 4a 0c 89 4a 10 89 4a 14 89 4a 18 89 4a 1c 8b 45 fc c1 e0 05 8b 4d 08 8b 55 fc 89 54 01 18 8b 45 fc c1 e0 05 8b 4d 08 c7 44 01 1c 00 00 00 00 eb ac } //00 00 
		$a_00_2 = {5d 04 00 00 3d 94 04 80 5c 2e 00 00 3e 94 04 80 00 00 01 00 32 00 18 00 52 61 6e 73 6f 6d 3a 57 69 6e 33 32 2f 52 79 75 6b 2e 5a 55 21 73 6d 73 00 00 01 40 05 82 70 00 04 00 ce 09 00 00 ea 35 f0 04 78 71 00 00 7b 5d 04 00 00 3e 94 04 80 5c 3d 00 00 3f 94 04 80 00 00 01 00 2e 00 27 00 42 65 68 61 76 } //69 6f 
	condition:
		any of ($a_*)
 
}