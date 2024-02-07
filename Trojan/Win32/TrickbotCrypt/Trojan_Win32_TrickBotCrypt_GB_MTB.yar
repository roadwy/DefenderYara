
rule Trojan_Win32_TrickBotCrypt_GB_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c2 33 d2 f7 35 90 01 04 a1 90 01 04 2b d3 48 0f af 05 90 01 04 03 fa 03 c7 8a 14 08 8b 44 24 18 8a 18 32 da 8b 54 24 20 88 18 90 00 } //01 00 
		$a_01_1 = {39 70 57 4e 57 6e 3c 38 55 6f 38 43 33 33 69 79 44 25 37 3f 59 33 5a 57 66 3c 57 6d 43 6e 39 44 6c 4a 7a 67 57 45 55 4c 28 50 42 78 4a 53 65 79 3f 38 4b 2a 44 3c 61 3f 26 47 78 69 6e 30 63 31 30 56 4c 29 3f 24 29 3e 56 31 34 69 67 66 36 65 75 55 6b 78 71 25 73 2a 35 4f 51 4c 67 77 6f 4c 24 4c 48 6b 41 3c 32 69 30 72 68 6e 2b 34 79 4c 69 43 47 38 43 74 67 } //00 00  9pWNWn<8Uo8C33iyD%7?Y3ZWf<WmCn9DlJzgWEUL(PBxJSey?8K*D<a?&Gxin0c10VL)?$)>V14igf6euUkxq%s*5OQLgwoL$LHkA<2i0rhn+4yLiCG8Ctg
	condition:
		any of ($a_*)
 
}