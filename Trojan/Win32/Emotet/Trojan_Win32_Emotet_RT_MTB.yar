
rule Trojan_Win32_Emotet_RT_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 d1 2b d0 8b 90 02 05 8a 18 8a 0c 32 32 d9 8b 90 02 05 88 18 8b 90 02 05 40 3b c1 89 90 02 05 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f0 0f b6 44 24 90 01 01 57 99 bf ab 05 00 00 f7 ff 80 c2 3d 85 f6 76 90 01 01 8a 01 32 c2 02 c2 88 01 41 83 ee 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 00 00 f7 fb 8b 44 24 90 01 01 8a 04 08 41 81 f9 90 01 01 69 00 00 8a 1c 17 88 5c 0e 90 01 01 88 04 2a 7c 90 00 } //01 00 
		$a_80_1 = {56 69 40 42 5a 56 26 2a 4b 72 68 39 68 46 5e 51 64 21 69 69 70 64 6a 31 25 23 76 64 40 48 5a 76 33 47 45 62 4f 30 54 6e 63 74 3f 73 51 57 57 66 62 25 62 6b 72 32 65 4f 31 59 38 75 21 67 62 28 58 53 36 6b 49 68 74 51 65 62 52 78 44 29 4c 21 5a 51 55 56 4d 61 5a 56 5e 66 5a 5f 30 39 4d 46 26 } //Vi@BZV&*Krh9hF^Qd!iipdj1%#vd@HZv3GEbO0Tnct?sQWWfb%bkr2eO1Y8u!gb(XS6kIhtQebRxD)L!ZQUVMaZV^fZ_09MF&  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_RT_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_81_0 = {56 56 72 53 52 49 4d 6c 36 30 6f 57 44 70 74 42 5a 7a 67 51 6f 70 4c 56 64 67 33 69 79 70 32 36 67 43 56 67 76 7a 74 6c 49 6d 35 44 37 30 47 4c 39 61 46 33 6d 37 54 6c 59 77 59 57 42 6a 54 74 73 38 33 48 7a 75 74 32 77 43 41 47 46 4b 50 4e 64 6f 63 6d 39 38 47 33 57 66 35 65 52 37 } //01 00 
		$a_81_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_81_2 = {47 65 74 53 74 72 69 6e 67 54 79 70 65 57 } //01 00 
		$a_81_3 = {47 65 74 43 50 49 6e 66 6f } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_RT_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {70 36 4e 77 6b 33 2a 41 33 49 63 45 49 4b 65 24 4a 3e 49 65 69 3c 3f 47 52 64 34 6a 79 63 30 39 59 52 45 61 40 2b 54 59 3c 21 65 2b 45 58 42 53 45 44 58 6e 59 6e 77 70 45 3c 69 57 25 73 6a 56 59 38 30 43 5e 73 63 3c 41 51 23 77 63 57 75 4d 70 62 4f 28 74 69 42 55 6d 44 5e 54 72 4e 28 35 62 29 2b 74 72 5a 76 71 4c 56 35 24 41 2a 37 31 56 5a } //p6Nwk3*A3IcEIKe$J>Iei<?GRd4jyc09YREa@+TY<!e+EXBSEDXnYnwpE<iW%sjVY80C^sc<AQ#wcWuMpbO(tiBUmD^TrN(5b)+trZvqLV5$A*71VZ  01 00 
		$a_03_1 = {83 c4 04 f7 d8 50 ff 15 90 01 04 89 45 90 01 01 eb 90 02 04 6a 40 68 00 30 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_RT_MTB_6{
	meta:
		description = "Trojan:Win32/Emotet.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0d 00 10 00 00 50 56 53 6a ff ff 15 90 01 04 eb 90 00 } //0a 00 
		$a_03_1 = {0b e8 55 57 6a 00 6a ff ff 15 90 01 04 e9 90 00 } //01 00 
		$a_80_2 = {31 78 32 4c 47 72 6a 68 66 67 3f 6f 6c 28 56 4a 33 71 58 33 70 59 6c 34 70 62 68 69 57 4f 55 64 24 65 63 77 26 4d 34 70 58 6e 21 79 32 4f 40 41 26 36 26 6f 3e 4f 40 6c 44 65 52 47 5e 4b 66 6f 68 52 55 29 74 23 48 53 25 4c 41 4d 64 45 5e 50 4f 5e 33 32 25 2a 56 67 61 5e 28 2a 3c 73 5e 6c 36 46 73 51 2a 26 77 51 52 37 72 } //1x2LGrjhfg?ol(VJ3qX3pYl4pbhiWOUd$ecw&M4pXn!y2O@A&6&o>O@lDeRG^KfohRU)t#HS%LAMdE^PO^32%*Vga^(*<s^l6FsQ*&wQR7r  01 00 
		$a_80_3 = {29 32 78 6d 67 24 33 25 4a 23 67 5a 70 45 2a 72 6d 48 30 2a 4d 24 25 26 39 2a 54 61 38 6f 55 3c 5e 7a 29 37 47 29 43 49 39 42 41 31 31 32 5a 7a 4d 68 54 2b 79 6d 75 36 41 48 49 37 64 66 31 76 41 7a 7a 44 33 49 6f 6a 76 66 5a 77 44 71 58 43 55 79 48 62 3c 75 } //)2xmg$3%J#gZpE*rmH0*M$%&9*Ta8oU<^z)7G)CI9BA112ZzMhT+ymu6AHI7df1vAzzD3IojvfZwDqXCUyHb<u  00 00 
	condition:
		any of ($a_*)
 
}