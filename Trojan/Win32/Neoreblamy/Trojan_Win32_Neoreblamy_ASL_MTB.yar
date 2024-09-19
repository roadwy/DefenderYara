
rule Trojan_Win32_Neoreblamy_ASL_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 10 00 00 "
		
	strings :
		$a_01_0 = {6a 52 68 6b 54 66 67 53 45 71 51 47 71 63 6e 4d 62 59 48 52 62 79 4d 79 4d 53 4e 4b 6a 55 } //1 jRhkTfgSEqQGqcnMbYHRbyMyMSNKjU
		$a_01_1 = {55 76 4a 63 54 41 67 48 57 43 79 44 71 43 4a 74 4b 67 69 4b 73 61 78 57 67 78 45 67 56 4e } //1 UvJcTAgHWCyDqCJtKgiKsaxWgxEgVN
		$a_01_2 = {45 53 58 51 6f 65 58 45 6a 53 46 64 5a 63 46 48 4e 77 4e 4a 75 46 4d 6f 57 57 72 78 59 42 58 61 6e 6c 73 79 48 } //1 ESXQoeXEjSFdZcFHNwNJuFMoWWrxYBXanlsyH
		$a_01_3 = {71 65 58 59 44 69 4e 63 41 58 62 74 69 55 4b 6e 77 4d 62 73 46 44 6a 59 57 62 67 6c 55 64 6c 58 6a 76 } //1 qeXYDiNcAXbtiUKnwMbsFDjYWbglUdlXjv
		$a_01_4 = {53 7a 63 6b 41 45 4d 6d 53 51 77 63 62 67 42 4f 4d 6b 6e 57 58 6a 46 56 65 47 65 53 4f 58 78 67 6b 75 } //1 SzckAEMmSQwcbgBOMknWXjFVeGeSOXxgku
		$a_01_5 = {4f 6a 72 72 4b 6c 53 63 43 6b 4b 68 4a 78 77 54 7a 79 67 7a 69 62 4f 50 75 72 58 6d 6b 56 77 62 63 6c 4c 78 42 } //1 OjrrKlScCkKhJxwTzygzibOPurXmkVwbclLxB
		$a_01_6 = {63 68 44 66 71 70 67 6d 67 5a 72 46 71 54 46 45 78 58 66 47 74 6f 54 74 6d 66 6d 4c 61 74 49 5a 64 61 53 7a 63 5a 4c 73 6a 78 78 59 59 4e 72 42 58 6b 4a } //1 chDfqpgmgZrFqTFExXfGtoTtmfmLatIZdaSzcZLsjxxYYNrBXkJ
		$a_01_7 = {52 61 47 44 6d 45 71 4e 58 4b 70 6f 50 6d 78 69 54 50 41 4e 52 6c 44 71 74 } //1 RaGDmEqNXKpoPmxiTPANRlDqt
		$a_01_8 = {4f 6f 65 4d 4e 6d 75 57 50 6e 59 55 6e 56 6c 45 6c 58 67 52 75 61 55 4b 63 49 44 68 5a 61 } //1 OoeMNmuWPnYUnVlElXgRuaUKcIDhZa
		$a_01_9 = {48 56 52 56 75 5a 53 78 67 47 77 58 4a 41 68 6c 65 4a 51 6c 53 59 62 4d 41 63 4b 42 74 75 } //1 HVRVuZSxgGwXJAhleJQlSYbMAcKBtu
		$a_01_10 = {50 54 70 50 4b 57 6a 6c 66 64 44 65 47 70 4e 6d 54 46 51 43 5a 6e 6f 51 73 64 79 41 53 67 51 4e 6d 74 } //1 PTpPKWjlfdDeGpNmTFQCZnoQsdyASgQNmt
		$a_01_11 = {42 43 69 5a 58 4d 75 50 79 52 6e 77 76 45 4b 6d 6a 69 53 79 47 52 6e 78 70 6b 43 53 68 49 7a 6c 51 56 5a 75 69 78 4b 44 41 77 } //1 BCiZXMuPyRnwvEKmjiSyGRnxpkCShIzlQVZuixKDAw
		$a_01_12 = {4d 43 4c 77 68 6a 6c 46 6e 4e 46 52 74 48 44 61 4e 6a 54 76 6e 47 62 61 6f 41 59 61 } //1 MCLwhjlFnNFRtHDaNjTvnGbaoAYa
		$a_01_13 = {78 42 7a 58 73 4d 56 61 71 61 71 4d 78 63 6a 75 68 43 74 5a 4d 48 49 77 6a 7a 75 42 45 43 57 48 75 56 } //1 xBzXsMVaqaqMxcjuhCtZMHIwjzuBECWHuV
		$a_01_14 = {59 66 73 45 59 4d 71 44 6a 64 74 6a 79 52 41 45 6c 55 41 50 77 70 58 45 6a 54 79 4b 62 46 71 } //1 YfsEYMqDjdtjyRAElUAPwpXEjTyKbFq
		$a_01_15 = {50 74 51 50 7a 64 66 44 67 59 73 71 75 6f 61 55 57 6b 48 47 73 67 75 45 59 54 78 6c 4c 6a 6e 6b 76 4b 6d 72 50 47 77 } //1 PtQPzdfDgYsquoaUWkHGsguEYTxlLjnkvKmrPGw
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=4
 
}