
rule Trojan_Win32_EmotetCrypt_DM_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 5c 24 14 0f b6 14 3b 03 c2 33 d2 f7 35 ?? ?? ?? ?? 03 ca 8d 04 71 8a 0c 38 8b 44 24 20 30 08 ff 44 24 18 8b 44 24 18 3b 44 24 28 0f 82 } //1
		$a_81_1 = {43 36 4e 65 3c 26 21 6e 37 62 3f 54 4b 6a 30 77 6b 75 3c 29 79 51 4b 42 33 78 42 73 28 4f 79 45 30 34 28 75 31 66 78 79 69 62 35 68 68 28 42 53 45 44 78 52 61 73 56 62 3c 35 6c 76 65 4a 42 37 41 26 57 68 35 51 6b 34 6c 29 55 31 58 4a 4c 4f 30 79 4b 64 4d 67 67 52 53 53 64 2a 66 35 } //1 C6Ne<&!n7b?TKj0wku<)yQKB3xBs(OyE04(u1fxyib5hh(BSEDxRasVb<5lveJB7A&Wh5Qk4l)U1XJLO0yKdMggRSSd*f5
		$a_03_2 = {8b 5c 24 28 0f b6 14 1a 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 20 2b d1 8a 0c 1a 30 08 ff 44 24 18 8b 44 24 18 3b 44 24 30 0f 82 } //1
		$a_81_3 = {4f 30 21 66 3f 63 7a 6d 3f 39 63 68 68 75 6d 29 69 66 24 24 5a 46 30 36 63 69 2a 40 38 32 3c 33 4a 49 3f 6f 4b 62 7a 5e 34 21 50 63 44 75 70 76 68 61 6b 49 66 62 56 43 7a 4a 61 77 65 62 49 31 6a 79 47 79 6a 68 2a 6c 50 62 65 76 30 73 31 4d 6b 61 71 68 53 6e 3c 41 64 29 29 61 61 53 24 78 34 2b 3f 43 3c 63 74 30 31 2a 3c 5a 69 74 } //1 O0!f?czm?9chhum)if$$ZF06ci*@82<3JI?oKbz^4!PcDupvhakIfbVCzJawebI1jyGyjh*lPbev0s1MkaqhSn<Ad))aaS$x4+?C<ct01*<Zit
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}