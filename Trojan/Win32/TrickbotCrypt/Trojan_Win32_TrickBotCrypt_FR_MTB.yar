
rule Trojan_Win32_TrickBotCrypt_FR_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 11 03 c2 33 d2 f7 35 90 01 04 89 55 f0 8b 45 f0 03 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 0f af 0d 90 01 04 03 c1 2b 05 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 2b c2 2b 05 90 01 04 2b 05 90 01 04 8b 4d 08 0f b6 14 01 8b 45 0c 03 45 f4 0f b6 08 33 ca 8b 55 0c 03 55 f4 88 0a e9 90 00 } //10
		$a_81_1 = {74 38 25 67 6c 50 2a 5f 70 69 79 75 61 31 62 3c 28 34 40 6b 74 6a 66 58 62 69 59 75 78 38 56 38 29 4d 72 48 3f 4e 39 3c 29 58 4a 50 38 28 76 21 66 65 65 50 49 4d 4b 71 34 78 49 40 41 74 3c 31 35 4e 5f 71 54 52 52 77 5a 62 67 50 48 5e 3f 44 51 4d 52 39 6a 78 5e 30 57 30 46 2b 4c } //10 t8%glP*_piyua1b<(4@ktjfXbiYux8V8)MrH?N9<)XJP8(v!feePIMKq4xI@At<15N_qTRRwZbgPH^?DQMR9jx^0W0F+L
		$a_81_2 = {67 62 50 5f 2b 66 6f 35 24 7a 53 39 2a 67 7a 39 62 4c 33 7a 3f 4d 45 6f 64 79 2a 4b 30 5f 23 42 2b 23 36 58 43 78 40 36 44 74 74 59 37 53 39 2a 68 4a 32 57 28 43 5e 59 5e 32 4a 7a 69 79 2a 3c 66 21 } //10 gbP_+fo5$zS9*gz9bL3z?MEody*K0_#B+#6XCx@6DttY7S9*hJ2W(C^Y^2Jziy*<f!
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10) >=10
 
}