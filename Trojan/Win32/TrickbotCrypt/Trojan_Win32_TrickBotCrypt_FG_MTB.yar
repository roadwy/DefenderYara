
rule Trojan_Win32_TrickBotCrypt_FG_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 0e 89 54 24 90 01 01 0f b6 d3 03 c2 33 d2 f7 35 90 01 04 8b 44 24 90 01 01 8a 18 8a 14 0a 32 da 88 18 8b 44 24 90 01 01 45 3b e8 72 90 00 } //1
		$a_81_1 = {4e 3e 45 33 4a 72 57 3e 33 39 78 44 6f 42 61 2a 42 72 34 6e 42 4c 40 4b 73 73 4a 47 38 4d 76 62 28 58 29 68 63 2a 51 33 29 6e 28 3e 40 48 2a 28 38 5a 37 7a 3c 5a 32 3c 6e 5f 32 33 74 6b 58 6c 47 68 5a 37 6f 42 77 26 44 39 59 69 29 50 71 6c 6c 21 71 42 61 74 44 6c 57 48 } //1 N>E3JrW>39xDoBa*Br4nBL@KssJG8Mvb(X)hc*Q3)n(>@H*(8Z7z<Z2<n_23tkXlGhZ7oBw&D9Yi)Pqll!qBatDlWH
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}