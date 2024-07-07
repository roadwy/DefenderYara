
rule Trojan_Win32_Emotet_ffhh_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ffhh!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6b 61 6f 64 33 72 33 79 30 38 63 62 30 71 78 39 6c 6c 6f 68 61 38 68 34 36 61 } //1 kaod3r3y08cb0qx9lloha8h46a
		$a_01_1 = {64 38 68 69 61 31 77 79 73 37 6c 70 70 61 33 73 35 30 6c 6f 6a 74 } //1 d8hia1wys7lppa3s50lojt
		$a_01_2 = {73 6b 69 39 78 6f 61 6c 65 34 65 64 70 63 33 61 36 64 78 } //1 ski9xoale4edpc3a6dx
		$a_01_3 = {77 67 72 6e 74 65 6f 33 69 75 6a 78 } //1 wgrnteo3iujx
		$a_01_4 = {6c 34 37 32 61 7a 6b 61 70 6f 78 74 } //1 l472azkapoxt
		$a_01_5 = {77 71 39 6f 6d 31 30 6e 32 38 31 68 } //1 wq9om10n281h
		$a_01_6 = {66 76 6c 66 66 76 62 6b 62 64 6f 36 39 } //1 fvlffvbkbdo69
		$a_01_7 = {65 79 37 39 6e 34 79 39 77 67 30 61 77 6f 77 6a 64 61 30 30 77 71 72 6d 68 36 70 74 39 67 38 } //1 ey79n4y9wg0awowjda00wqrmh6pt9g8
		$a_01_8 = {78 67 78 64 39 37 35 72 78 61 6a 6e 73 39 62 7a 68 70 66 7a 61 61 76 72 75 70 66 } //1 xgxd975rxajns9bzhpfzaavrupf
		$a_01_9 = {63 38 61 32 6a 6b 7a 37 62 71 35 35 37 63 35 66 38 6d 7a 7a 7a 67 6f 64 65 78 6f 37 33 79 } //1 c8a2jkz7bq557c5f8mzzzgodexo73y
		$a_01_10 = {7a 34 71 7a 64 6c 70 65 64 67 61 70 73 32 72 62 62 31 64 6c 77 } //1 z4qzdlpedgaps2rbb1dlw
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}