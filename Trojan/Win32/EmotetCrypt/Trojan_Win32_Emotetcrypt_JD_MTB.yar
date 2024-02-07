
rule Trojan_Win32_Emotetcrypt_JD_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.JD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f af d7 2b d0 a1 90 01 04 2b d0 42 0f af 15 90 01 04 8b 0d 90 01 04 03 c9 2b d1 8b 0d 90 01 04 2b d1 8b 4c 24 30 03 d0 8a 45 00 03 d1 8b 4c 24 3c 8a 14 1a 32 c2 88 45 00 90 00 } //01 00 
		$a_01_1 = {58 40 69 28 4f 35 53 4e 33 56 6e 50 3f 41 36 5f 66 72 5e 56 59 2b 40 52 5f 6d 39 24 3c 46 75 34 70 4e 5f 48 23 79 47 4d 76 51 29 35 46 55 56 69 31 36 34 5e 5e 31 24 7a 6d 75 6d 45 31 46 7a } //00 00  X@i(O5SN3VnP?A6_fr^VY+@R_m9$<Fu4pN_H#yGMvQ)5FUVi164^^1$zmumE1Fz
	condition:
		any of ($a_*)
 
}