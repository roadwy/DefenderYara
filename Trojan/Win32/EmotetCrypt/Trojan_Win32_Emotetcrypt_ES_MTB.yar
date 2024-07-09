
rule Trojan_Win32_Emotetcrypt_ES_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 1a 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 e8 0f af e8 a1 ?? ?? ?? ?? 2b ce 0f af cf 03 e9 03 c0 2b e8 8b 44 24 20 2b ee 03 d3 8a 0c 6a 30 08 } //1
		$a_81_1 = {3c 7a 64 2a 62 30 23 74 3f 72 47 37 6b 7a 77 46 70 58 75 25 74 57 32 72 5e 40 6c 68 56 6a 41 3f 6f 7a 51 25 4b 66 6c 46 62 3f 54 30 4e 69 41 23 21 5a 38 } //1 <zd*b0#t?rG7kzwFpXu%tW2r^@lhVjA?ozQ%KflFb?T0NiA#!Z8
		$a_81_2 = {5e 5a 77 50 47 77 6f 57 4a 66 21 76 78 4e 67 34 36 41 4f 4d 33 24 4a 56 30 5e 79 34 47 63 79 39 40 53 33 2b 28 4a 67 70 6f 2a 5f 6c 68 65 2b 35 68 6a 52 69 4e 46 67 26 6c 76 62 4b 42 68 32 } //1 ^ZwPGwoWJf!vxNg46AOM3$JV0^y4Gcy9@S3+(Jgpo*_lhe+5hjRiNFg&lvbKBh2
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}