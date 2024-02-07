
rule Trojan_Win32_TrickBotCrypt_FV_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8a 14 0f 03 c2 33 d2 f7 35 90 01 04 a1 90 01 04 8d 04 80 2b d0 03 d5 8b 2d 90 01 04 03 d5 8b 6c 24 10 8a 14 0a 8a 45 00 32 c2 43 88 45 00 8b 44 24 20 90 00 } //05 00 
		$a_81_1 = {31 50 2b 33 46 4e 3f 66 65 28 45 41 69 42 62 49 56 25 71 54 6a 25 41 6a 5f 4c 63 42 26 73 32 70 4b 39 79 59 68 23 72 49 48 3c 6d 49 4d 26 62 58 2a 6d 21 5e 28 70 26 75 6c 5e 51 23 2a 39 3e 78 42 67 61 6d 29 33 64 59 79 48 6f 5e 44 75 24 46 3e 7a } //00 00  1P+3FN?fe(EAiBbIV%qTj%Aj_LcB&s2pK9yYh#rIH<mIM&bX*m!^(p&ul^Q#*9>xBgam)3dYyHo^Du$F>z
	condition:
		any of ($a_*)
 
}