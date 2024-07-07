
rule Trojan_Win32_Emotetcrypt_RWA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c1 c1 e9 08 0f b6 c0 33 8c 84 90 01 04 83 ee 01 75 90 01 01 8b 5c 24 90 01 01 f6 d1 8b 44 24 90 01 01 88 0c 03 43 89 5c 24 90 01 01 81 fb ce 40 00 00 73 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_RWA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {43 72 36 69 57 65 4e 71 62 48 69 70 5a 63 65 62 73 6f 48 32 58 54 76 57 42 66 79 3f 39 21 55 70 48 6a 6d 48 30 74 30 72 31 46 36 69 4a 75 28 48 7a 3e 38 2b 34 42 21 51 39 53 63 70 52 56 67 79 6f 76 4c 65 23 78 28 55 37 7a 42 30 30 43 6d 7a 30 3e 79 6e 6c 24 23 5f 55 37 40 6a 50 3f 40 29 63 41 78 65 71 55 30 49 32 78 74 5e 73 24 } //Cr6iWeNqbHipZcebsoH2XTvWBfy?9!UpHjmH0t0r1F6iJu(Hz>8+4B!Q9ScpRVgyovLe#x(U7zB00Cmz0>ynl$#_U7@jP?@)cAxeqU0I2xt^s$  1
		$a_03_1 = {b9 20 1f 00 00 f7 f1 8b 45 90 01 01 03 55 90 01 01 8b 4d 90 01 01 0f b6 04 02 8b 55 90 01 01 30 04 0a 41 89 4d 90 01 01 3b cf b9 20 1f 00 00 72 90 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotetcrypt_RWA_MTB_3{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {43 36 4e 65 3c 26 21 6e 37 62 3f 54 4b 6a 30 77 6b 75 3c 29 79 51 4b 42 33 78 42 73 28 4f 79 45 30 34 28 75 31 66 78 79 69 62 35 68 68 28 42 53 45 44 78 52 61 73 56 62 3c 35 6c 76 65 4a 42 37 41 26 57 68 35 51 6b 34 6c 29 55 31 58 4a 4c 4f 30 79 4b 64 4d 67 67 52 53 53 64 2a 66 35 } //5 C6Ne<&!n7b?TKj0wku<)yQKB3xBs(OyE04(u1fxyib5hh(BSEDxRasVb<5lveJB7A&Wh5Qk4l)U1XJLO0yKdMggRSSd*f5
		$a_81_1 = {25 71 51 6e 31 2b 25 32 44 74 61 68 48 38 4b 50 25 5f 4a 45 73 4e 54 49 65 46 75 57 70 34 36 4f 3c 73 71 35 6a 32 69 56 4e 30 74 6c 28 6d 53 62 71 67 62 35 7a 68 32 29 59 51 24 44 35 73 5e 38 6a } //5 %qQn1+%2DtahH8KP%_JEsNTIeFuWp46O<sq5j2iVN0tl(mSbqgb5zh2)YQ$D5s^8j
		$a_03_2 = {33 d2 f7 35 90 01 04 03 ca 8d 04 71 8a 0c 38 8b 44 24 90 01 01 30 08 ff 44 24 90 01 01 8b 44 24 90 01 01 3b 44 24 90 01 01 0f 90 00 } //1
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_03_2  & 1)*1) >=6
 
}