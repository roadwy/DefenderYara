
rule Trojan_Win32_TrickBotCrypt_EA_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 0f b6 55 90 01 01 33 ca 8b 45 90 01 01 2b 45 90 01 01 0f b6 d0 81 e2 ff 00 00 00 33 ca 8b 45 90 01 01 88 08 8b 4d 90 01 01 03 4d 90 01 01 89 4d 90 01 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBotCrypt_EA_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 0e 03 c2 33 d2 f7 35 90 01 04 a1 90 01 04 8b d8 0f af d8 4b 0f af d8 a1 90 01 04 03 d3 2b d0 8b 44 24 10 8a 18 8a 14 0a 32 da 88 18 90 00 } //5
		$a_81_1 = {38 6f 46 62 6f 23 48 55 68 7a 21 4e 5e 7a 56 4e 23 7a 66 65 5a 67 5f 73 4d 6e 58 3f 50 26 37 45 36 25 69 41 23 4d 54 26 6f 36 36 69 74 24 74 5f 37 4a 51 69 62 59 66 52 65 74 37 48 69 50 3f 5f 2a 56 30 37 76 4d 57 62 } //5 8oFbo#HUhz!N^zVN#zfeZg_sMnX?P&7E6%iA#MT&o66it$t_7JQibYfRet7HiP?_*V07vMWb
		$a_81_2 = {51 66 52 43 4d 76 33 45 48 59 59 3c 57 36 25 61 50 55 59 47 55 6a 74 2a 36 47 23 26 50 26 38 46 61 62 57 47 65 43 40 4f 6a 26 23 79 49 26 48 70 6b 6c 42 49 31 4a 79 50 23 45 54 76 5f 57 56 52 57 25 42 53 5a 47 29 76 26 63 51 3f 6e 79 73 7a 37 4a 48 3e 21 46 78 43 7a 2a 69 66 4c 4f 4e 21 79 31 67 4f 37 6e 3f 59 6a 30 37 30 29 42 } //5 QfRCMv3EHYY<W6%aPUYGUjt*6G#&P&8FabWGeC@Oj&#yI&HpklBI1JyP#ETv_WVRW%BSZG)v&cQ?nysz7JH>!FxCz*ifLON!y1gO7n?Yj070)B
		$a_81_3 = {4e 54 28 5a 70 23 5e 23 40 23 36 49 5e 41 6b 74 3e 4a 6c 56 26 3e 50 59 77 65 34 30 6a 61 5a 25 6e 4d 58 4e 40 53 2a 4f 21 6a 6c 4f 4a 44 6d 37 4d 28 76 64 3f 55 4f 25 78 3f 42 6d 48 4c 6d 78 26 28 28 3f 51 64 68 5a 28 25 5a 52 77 5e 32 67 64 4a 3e 65 35 44 28 4f } //5 NT(Zp#^#@#6I^Akt>JlV&>PYwe40jaZ%nMXN@S*O!jlOJDm7M(vd?UO%x?BmHLmx&((?QdhZ(%ZRw^2gdJ>e5D(O
		$a_81_4 = {54 6a 79 36 6f 23 6c 57 6d 67 75 35 21 49 30 3e 34 6c 77 79 73 29 4f 5e 4c 71 2b 29 6f 5e 6b 72 55 58 42 38 4e 2b 35 64 5f 28 55 43 64 4e 43 6a 70 64 55 71 53 69 42 2a 24 6c 33 24 45 52 6e 4c 31 34 78 66 52 6a 2a 36 21 3f 23 78 32 48 78 } //5 Tjy6o#lWmgu5!I0>4lwys)O^Lq+)o^krUXB8N+5d_(UCdNCjpdUqSiB*$l3$ERnL14xfRj*6!?#x2Hx
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*5+(#a_81_4  & 1)*5) >=5
 
}