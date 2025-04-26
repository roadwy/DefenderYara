
rule Trojan_Win64_Dridex_DK_MTB{
	meta:
		description = "Trojan:Win64/Dridex.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 03 00 00 "
		
	strings :
		$a_00_0 = {4c 8b d9 0f b6 d2 49 b9 01 01 01 01 01 01 01 01 4c 0f af ca 49 83 f8 10 0f 86 f2 00 00 00 66 49 0f 6e c1 66 0f 60 c0 49 81 f8 80 00 00 00 77 10 } //10
		$a_00_1 = {48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 10 40 8a 3a 48 8b da 4c 8b c1 40 84 ff } //10
		$a_80_2 = {6b 64 74 6c 74 64 79 62 69 70 } //kdtltdybip  3
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_80_2  & 1)*3) >=23
 
}
rule Trojan_Win64_Dridex_DK_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_00_0 = {48 83 ec 38 c7 44 24 30 de 9b 91 43 66 8b 44 24 36 66 83 f0 ff 66 89 44 24 36 e8 41 fa ff ff b9 01 00 00 00 ba 3c 93 29 67 41 89 d0 4c 2b 44 24 28 8b 54 24 30 81 c2 22 64 6e bc 4c 89 44 24 28 39 d0 89 4c 24 24 } //10
		$a_80_1 = {53 74 72 54 72 69 6d 57 } //StrTrimW  3
		$a_80_2 = {55 72 6c 55 6e 65 73 63 61 70 65 41 } //UrlUnescapeA  3
		$a_80_3 = {4d 70 72 41 64 6d 69 6e 49 6e 74 65 72 66 61 63 65 54 72 61 6e 73 70 6f 72 74 41 64 64 } //MprAdminInterfaceTransportAdd  3
		$a_80_4 = {47 65 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 49 6e 66 6f 57 } //GetUrlCacheEntryInfoW  3
		$a_80_5 = {48 49 43 4f 4e 5f 55 73 65 72 4d 61 72 73 68 61 6c } //HICON_UserMarshal  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=25
 
}
rule Trojan_Win64_Dridex_DK_MTB_3{
	meta:
		description = "Trojan:Win64/Dridex.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {6c 69 6b 65 77 65 6c 63 6f 6d 65 62 72 6f 77 73 65 72 41 } //likewelcomebrowserA  3
		$a_80_1 = {33 37 74 6f 47 4f 67 37 38 69 6e 73 63 6f 72 65 73 71 62 75 62 62 61 } //37toGOg78inscoresqbubba  3
		$a_80_2 = {56 4c 69 6e 63 6c 75 64 65 64 74 68 65 52 65 6c 65 61 73 65 61 6e 64 33 32 30 30 39 2c 62 65 72 65 63 65 69 76 69 6e 67 } //VLincludedtheReleaseand32009,bereceiving  3
		$a_80_3 = {43 4d 5f 47 65 74 5f 52 65 73 6f 75 72 63 65 5f 43 6f 6e 66 6c 69 63 74 5f 44 65 74 61 69 6c 73 57 } //CM_Get_Resource_Conflict_DetailsW  3
		$a_80_4 = {43 65 72 74 47 65 74 43 54 4c 43 6f 6e 74 65 78 74 50 72 6f 70 65 72 74 79 } //CertGetCTLContextProperty  3
		$a_80_5 = {49 77 36 77 68 69 63 68 39 69 55 31 25 68 } //Iw6which9iU1%h  3
		$a_80_6 = {44 65 6c 65 74 65 43 72 69 74 69 63 61 6c 53 65 63 74 69 6f 6e } //DeleteCriticalSection  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}