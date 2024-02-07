
rule Trojan_Win32_EmotetCrypt_DF_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 1c 0e 29 d0 8b 54 24 08 88 1c 0a 01 c1 89 4c 24 1c 8b 44 24 18 35 90 02 04 3d 90 02 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_EmotetCrypt_DF_MTB_2{
	meta:
		description = "Trojan:Win32/EmotetCrypt.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 14 08 e9 90 09 46 00 90 02 20 33 d1 a1 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 8b 4d 90 01 01 2b 0d 90 01 04 2b c8 2b 0d 90 01 04 03 0d 90 01 04 03 0d 90 01 04 8b 45 90 00 } //01 00 
		$a_03_1 = {33 c2 8b 0d 90 01 04 0f af 0d 90 01 04 0f af 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 8b 75 90 01 01 2b f2 2b f1 03 35 90 01 04 03 35 90 01 04 8b 4d 90 01 01 88 04 31 e9 90 00 } //01 00 
		$a_81_2 = {79 5f 66 76 41 32 66 75 56 23 71 68 5a 30 74 61 73 3e 69 40 3f 41 75 64 69 63 74 2a 78 6c 5f 47 28 47 77 57 25 58 4d 49 76 38 37 49 2b 3c 74 43 44 63 4b 4f 42 2a 76 73 6c } //01 00  y_fvA2fuV#qhZ0tas>i@?Audict*xl_G(GwW%XMIv87I+<tCDcKOB*vsl
		$a_81_3 = {61 5f 42 59 24 61 24 35 5e 30 69 6c 63 70 36 21 6b 48 67 42 53 58 51 4b 35 53 37 5f 25 56 62 29 61 43 6f 4f 39 5a 43 34 56 65 71 38 4e 68 45 4b 74 50 37 40 57 42 4f 4f 28 54 45 5a 54 3f 5e 6b 36 6c 62 5e 52 4c 42 51 75 29 21 41 54 29 46 6c 40 2a 54 47 61 24 68 2b 49 70 } //01 00  a_BY$a$5^0ilcp6!kHgBSXQK5S7_%Vb)aCoO9ZC4Veq8NhEKtP7@WBOO(TEZT?^k6lb^RLBQu)!AT)Fl@*TGa$h+Ip
		$a_81_4 = {28 5e 74 4d 4b 26 31 36 76 34 41 32 48 53 21 24 70 71 4b 76 43 53 30 41 57 3c 76 6e 6c 6e 6a 69 76 52 53 50 36 6d 4d 31 65 4e 32 53 71 6e 47 63 53 29 2a 6d 5a 73 6f 37 4d 45 57 4c 52 77 6b 6d 6b 49 31 } //00 00  (^tMK&16v4A2HS!$pqKvCS0AW<vnlnjivRSP6mM1eN2SqnGcS)*mZso7MEWLRwkmkI1
	condition:
		any of ($a_*)
 
}