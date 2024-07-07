
rule Trojan_Win32_Emotetcrypt_GT_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 1a 03 c1 99 b9 90 01 04 f7 f9 a1 90 01 04 8d 0c 85 90 01 04 b8 90 01 04 2b c1 0f af c6 8b c8 a1 90 01 04 8d 04 c0 2b c8 83 e9 90 01 01 0f af cf 03 d1 8b 0d 90 01 04 8d 04 76 03 d0 8d 04 8d 90 01 04 2b d0 0f b6 0c 1a 8b 44 24 90 01 01 30 08 90 00 } //1
		$a_81_1 = {53 66 26 7a 57 54 57 23 30 26 4b 53 26 48 79 58 23 37 66 46 48 44 72 74 55 42 74 29 47 6a 65 49 2b 39 38 45 72 64 45 4b 24 67 64 4b 23 52 } //1 Sf&zWTW#0&KS&HyX#7fFHDrtUBt)GjeI+98ErdEK$gdK#R
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}