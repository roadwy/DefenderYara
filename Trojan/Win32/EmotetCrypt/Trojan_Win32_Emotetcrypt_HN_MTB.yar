
rule Trojan_Win32_Emotetcrypt_HN_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 2a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8b ee 2b ef 0f af 2d ?? ?? ?? ?? 83 c5 03 0f af e9 8b c7 2b c6 83 e8 05 0f af c3 03 e8 a1 ?? ?? ?? ?? 03 54 24 2c 2b c8 0f af cf 03 e9 2b e8 8b 44 24 24 6b ed 03 8a 0c 2a 30 08 } //1
		$a_03_1 = {0f af c1 8b eb 2b e8 8b c7 0f af c6 45 0f af e9 03 2d ?? ?? ?? ?? 40 0f af c3 8b df 0f af de 0f af de 03 c5 6b db 03 6b c0 03 03 d0 a1 ?? ?? ?? ?? 83 c3 04 0f af df 8b f8 6b ff 03 8d 7c 3b ff 0f af f8 03 7c 24 28 8b 44 24 20 2b ce 49 0f af ce 03 fa 8a 0c 8f 30 08 } //1
		$a_81_2 = {69 6f 4a 57 54 38 63 6b 69 7a 39 69 54 3e 5f 4b 4c 4f 30 46 69 59 39 35 75 40 47 6a 56 46 52 2a 68 6c 38 3c 64 33 65 77 57 2b 44 61 29 67 61 67 49 4d 4e 66 6e 2b 3c 33 3f 4d 79 47 26 54 34 4b 4c 45 75 79 5e 64 3f 70 66 5a 3c 37 46 4d 6b 45 48 44 5e 73 59 3e 4b 49 4e 65 56 70 48 29 6b 5a 5f 63 67 55 59 58 53 74 37 63 2b 24 6f 33 48 4e 5f 5f 6c 55 3f 6a 58 6c } //1 ioJWT8ckiz9iT>_KLO0FiY95u@GjVFR*hl8<d3ewW+Da)gagIMNfn+<3?MyG&T4KLEuy^d?pfZ<7FMkEHD^sY>KINeVpH)kZ_cgUYXSt7c+$o3HN__lU?jXl
		$a_81_3 = {46 49 6e 37 5f 54 77 35 6d 52 21 53 61 47 4a 35 26 38 74 55 4e 21 48 66 69 68 26 70 76 58 21 3c 45 53 21 4f 39 78 65 66 34 70 53 6d 53 79 67 38 57 2a 40 62 48 33 6b 40 48 52 6b 3f 3f 30 3c 26 79 4f 64 4c 55 2b 34 4f 55 38 70 3c } //1 FIn7_Tw5mR!SaGJ5&8tUN!Hfih&pvX!<ES!O9xef4pSmSyg8W*@bH3k@HRk??0<&yOdLU+4OU8p<
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}