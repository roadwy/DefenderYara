
rule Trojan_Win32_Emotetcrypt_IF_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 1c 29 8b 44 24 20 0f b6 04 08 03 da 03 c3 33 d2 bb 90 01 04 f7 f3 8b 44 24 18 8a 00 8b 5c 24 34 88 44 24 13 8b c2 2b c6 8a 04 18 8b 5c 24 2c 88 04 0f 8a 44 24 12 02 44 24 13 41 ff 44 24 18 88 04 13 90 00 } //01 00 
		$a_81_1 = {73 56 48 56 45 39 3e 50 4e 66 4d 6e 79 4d 4b 35 69 25 28 6c 46 35 72 6e 63 68 49 3c 64 51 3c 4c 69 76 56 72 64 7a 54 55 2a 46 7a 34 28 4c 45 78 33 6d 30 71 38 59 4c 49 57 4d 24 4c 23 47 47 76 70 74 25 6b 5a 36 61 43 4a 72 39 65 47 53 56 51 77 7a 3c 5e 29 75 35 34 64 47 36 35 53 69 } //00 00  sVHVE9>PNfMnyMK5i%(lF5rnchI<dQ<LivVrdzTU*Fz4(LEx3m0q8YLIWM$L#GGvpt%kZ6aCJr9eGSVQwz<^)u54dG65Si
	condition:
		any of ($a_*)
 
}