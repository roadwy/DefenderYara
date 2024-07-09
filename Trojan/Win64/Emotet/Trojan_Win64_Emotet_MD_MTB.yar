
rule Trojan_Win64_Emotet_MD_MTB{
	meta:
		description = "Trojan:Win64/Emotet.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 98 49 8b c9 32 14 18 4b 8d 04 1b 49 0f af c9 49 0f af c8 49 2b cb 49 0f af c9 49 03 ca 48 2b c8 48 8d 04 4e 48 ff c6 48 03 c8 88 14 39 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Emotet_MD_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0d 00 00 "
		
	strings :
		$a_01_0 = {8a c2 48 83 c1 01 48 83 c2 01 83 e0 0f 42 0f b6 04 00 32 44 29 ff 48 83 ee 01 88 41 ff 75 } //10
		$a_01_1 = {f7 f9 48 63 ca 48 8b 44 24 30 0f b6 04 08 41 8b d0 33 d0 48 63 4c 24 40 48 8b 44 24 38 88 14 08 eb } //10
		$a_01_2 = {49 ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea 03 6b d2 0f 2b c2 48 63 c8 42 0f b6 04 11 41 32 44 29 ff 41 88 41 ff 45 3b c4 72 } //10
		$a_01_3 = {f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 05 48 6b c0 27 48 2b c8 48 63 c6 83 c6 01 0f b6 0c 01 41 32 4c 2d ff 41 3b f6 88 4d ff 0f 82 } //10
		$a_03_4 = {41 f7 e0 41 8b c0 41 83 c0 01 2b c2 d1 e8 03 c2 c1 e8 05 48 6b c0 ?? 48 2b c8 0f b6 04 19 ?? 32 44 ?? ff ?? 3b ?? 41 88 41 ff 72 } //10
		$a_03_5 = {f7 e6 48 63 c6 83 c6 01 c1 ea 03 48 8d 0c d2 48 8d 15 ?? ?? ?? ?? 48 c1 e1 02 48 2b d1 0f b6 0c 02 41 32 4c 2d ff 41 3b f6 88 4d ff 0f 82 } //10
		$a_01_6 = {6b 2b 29 30 7a 4d 58 74 68 45 79 31 25 38 7a } //1 k+)0zMXthEy1%8z
		$a_01_7 = {37 28 72 4b 4f 48 4d 5e 47 7a 31 56 51 39 67 50 63 } //1 7(rKOHM^Gz1VQ9gPc
		$a_01_8 = {4c 61 25 4a 79 3c 32 26 6a 42 31 34 34 6f } //1 La%Jy<2&jB144o
		$a_01_9 = {49 58 4f 3e 4f 4b 26 41 4f 77 74 24 28 65 36 4d 4c 51 79 2a 26 76 55 78 26 69 72 43 51 4f 65 6d 33 79 21 72 4e 4f } //1 IXO>OK&AOwt$(e6MLQy*&vUx&irCQOem3y!rNO
		$a_01_10 = {47 50 74 35 47 58 56 42 33 2a 30 4a 37 68 4a 46 4d 3f 3e 42 6a 71 38 69 73 5e 64 6d 32 6c 5e 28 76 36 72 51 3f 6f 37 35 37 76 44 35 } //1 GPt5GXVB3*0J7hJFM?>Bjq8is^dm2l^(v6rQ?o757vD5
		$a_01_11 = {2a 4a 21 75 36 78 25 43 25 55 21 41 35 2a 33 65 79 30 32 52 68 30 23 40 4d 55 7a 68 76 58 71 72 76 71 35 75 26 5a 4f 26 26 50 37 5f 6c 53 64 74 36 61 38 6e 6d } //1 *J!u6x%C%U!A5*3ey02Rh0#@MUzhvXqrvq5u&ZO&&P7_lSdt6a8nm
		$a_01_12 = {40 73 45 42 67 39 3c 6a 24 24 61 28 39 53 4c 3e 5f 58 4c 6b 5e 50 59 54 47 5e 55 78 69 55 32 6e 47 51 40 } //1 @sEBg9<j$$a(9SL>_XLk^PYTG^UxiU2nGQ@
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_03_4  & 1)*10+(#a_03_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=11
 
}