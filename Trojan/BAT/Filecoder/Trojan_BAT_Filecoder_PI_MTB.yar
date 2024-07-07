
rule Trojan_BAT_Filecoder_PI_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {4b 72 61 6b 65 6e } //Kraken  1
		$a_81_1 = {65 78 74 65 6e 73 69 6f 6e 5f 62 79 70 61 73 73 } //1 extension_bypass
		$a_81_2 = {32 6b 48 6a 67 42 55 78 36 51 51 53 6b 77 52 6e 4c 73 35 63 2f 41 64 62 6a 72 6f 44 55 34 6a 35 41 61 6e 43 61 62 72 70 6a 42 4c 6e 4b 43 57 47 4b 77 6d 6c 57 51 5a 52 } //1 2kHjgBUx6QQSkwRnLs5c/AdbjroDU4j5AanCabrpjBLnKCWGKwmlWQZR
		$a_81_3 = {47 52 53 59 6e 4b 4e 78 31 71 52 43 6f 69 43 50 51 71 4c 36 4d 6a 55 48 45 45 4f 58 6b 4d 4f 57 49 54 68 2f 43 61 63 77 51 44 4d 45 45 6e 32 53 6c 78 44 44 69 73 4c 76 79 62 64 6a 77 39 79 31 51 3d 3d } //1 GRSYnKNx1qRCoiCPQqL6MjUHEEOXkMOWITh/CacwQDMEEn2SlxDDisLvybdjw9y1Q==
		$a_81_4 = {74 61 72 67 65 74 5f 65 78 74 65 6e 73 69 6f 6e 73 } //1 target_extensions
		$a_81_5 = {61 63 63 64 62 } //1 accdb
		$a_81_6 = {62 61 63 6b 75 70 } //1 backup
		$a_81_7 = {62 61 6e 6b } //1 bank
		$a_81_8 = {62 6c 65 6e 64 } //1 blend
	condition:
		((#a_80_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}