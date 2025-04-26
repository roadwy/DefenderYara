
rule Trojan_Win32_Emotetcrypt_EL_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f af d8 a1 ?? ?? ?? ?? 0f af c3 8d 1c 06 a1 ?? ?? ?? ?? 29 c3 a1 ?? ?? ?? ?? 01 d8 89 c3 8b 45 08 01 d8 0f b6 00 31 c8 88 02 83 45 ec 01 8b 45 ec 3b 45 10 0f 82 } //10
		$a_81_1 = {52 48 71 5f 48 62 58 7a 4e 51 35 54 69 48 3c 25 61 6c 70 38 37 55 71 21 36 54 4c 33 6d 28 61 6b 50 30 42 4b 6d 51 36 35 75 35 76 48 78 3e 7a 4e 47 63 4f 76 6d 56 71 2a 68 49 41 6d 62 55 42 6a 58 23 66 5a 63 43 62 6e 28 25 53 29 31 26 25 7a 71 48 46 49 6f 78 49 2b 48 6d 77 4d 6d 6c 6c 2b 41 54 35 23 53 65 33 31 5f 25 38 37 40 58 31 47 40 4b } //1 RHq_HbXzNQ5TiH<%alp87Uq!6TL3m(akP0BKmQ65u5vHx>zNGcOvmVq*hIAmbUBjX#fZcCbn(%S)1&%zqHFIoxI+HmwMmll+AT5#Se31_%87@X1G@K
		$a_03_2 = {8b c3 0f af 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 83 c0 04 0f af 05 ?? ?? ?? ?? 03 d0 8d 47 01 0f af c7 2b d0 8b 44 24 1c 2b d3 2b d1 8a 0c 32 30 08 8b 44 24 14 40 89 44 24 14 3b 44 24 2c 0f 82 } //10
		$a_81_3 = {6f 45 68 6e 65 5a 4c 4a 67 4b 63 46 43 4b 78 62 51 63 4c 21 76 61 64 74 4f 42 43 35 58 39 23 75 77 6d 67 43 58 45 6c 75 35 6f 59 34 30 59 3c 42 39 56 38 78 26 4c 24 4f 63 4c 5a 50 66 76 42 33 28 25 6a 79 4f 5f 28 68 26 3c 55 44 54 26 } //1 oEhneZLJgKcFCKxbQcL!vadtOBC5X9#uwmgCXElu5oY40Y<B9V8x&L$OcLZPfvB3(%jyO_(h&<UDT&
		$a_81_4 = {4f 56 73 25 6d 5f 70 28 79 55 42 6f 45 65 77 58 37 66 32 58 41 61 7a 21 69 5e 73 33 4b 6e 47 67 } //1 OVs%m_p(yUBoEewX7f2XAaz!i^s3KnGg
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_03_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=11
 
}