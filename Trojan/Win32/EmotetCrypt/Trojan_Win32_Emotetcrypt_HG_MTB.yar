
rule Trojan_Win32_Emotetcrypt_HG_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 d0 8b 4d f0 2b 0d 90 01 04 2b 0d 90 01 04 2b 0d 90 01 04 2b 0d 90 01 04 2b 0d 90 01 04 2b 0d 90 01 04 2b 0d 90 01 04 2b 0d 90 01 04 8b 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 90 01 04 0f af 05 90 01 04 8b 4d f4 2b 0d 90 01 04 03 45 0c 88 14 08 90 00 } //1
		$a_81_1 = {28 50 79 62 7a 6e 78 51 4e 69 3c 7a 69 6b 79 4d 54 56 65 4d 6d 55 29 6a 4f 4f 5e 54 45 40 55 3e 3e 46 6c 4b 21 4d 30 6f 52 50 4a 67 78 36 43 79 3f 6f 48 79 67 63 30 6b 74 3e 66 46 26 26 49 66 79 29 50 6f 32 6b 28 51 2b 44 4f 62 38 6f 54 21 2a 51 39 66 51 23 4f 36 69 34 66 4d 23 75 32 51 } //1 (PybznxQNi<zikyMTVeMmU)jOO^TE@U>>FlK!M0oRPJgx6Cy?oHygc0kt>fF&&Ify)Po2k(Q+DOb8oT!*Q9fQ#O6i4fM#u2Q
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}