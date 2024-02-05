
rule Trojan_Win32_InjectorCrypt_SK_MTB{
	meta:
		description = "Trojan:Win32/InjectorCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_12_0 = {5e 5b c9 c2 0c 00 90 0a 80 00 55 89 e5 83 ec 28 53 56 57 01 db 8b 75 08 43 89 f7 11 d9 eb 90 02 05 8b 5d 10 87 d1 83 7d 0c 00 74 90 00 01 } //00 3f 
		$a_5f_1 = {5b c9 c2 0c 00 90 0a 50 00 09 d9 ac 6b d2 90 01 01 eb } //90 02 
		$a_31_2 = {0f af d0 aa 01 } //55 fc 
		$a_90_3 = {05 1f c1 c3 90 02 04 89 c1 eb 90 02 05 03 5d 10 2d 90 02 04 ff 4d 0c f7 d9 eb 90 00 00 00 5d 04 00 00 40 26 04 80 5c 23 00 00 41 26 04 80 00 00 01 00 05 00 0d 00 a4 21 4b 61 73 69 64 65 74 21 4d 53 52 00 00 06 40 05 82 64 00 04 00 67 26 00 00 20 3e e0 03 68 d0 24 2e 51 b3 e4 0e 1d 07 00 00 01 10 98 f0 cb e6 ab 89 fc 30 9c aa 8d ac 40 14 a2 5b 6c 2e 63 02 67 26 00 00 06 c2 77 48 5c 88 fa 85 36 54 8e ea 85 0a 00 00 01 10 0c ba 44 09 80 13 84 f3 3a 56 83 a9 2f 28 94 40 7a d2 e6 b3 67 26 00 00 0b 09 ce 69 9d ff 43 4e 53 bc 2e 02 11 07 00 00 01 10 8e 81 52 fb 97 1f 97 73 1e 6b b4 6d 33 47 34 48 a3 f7 aa 6b 67 26 00 00 c7 14 0d 81 67 d0 6d de 14 23 bc 3a 90 07 00 00 01 10 7c 25 51 1c 66 fb 10 ee ae 5c } //80 71 
	condition:
		any of ($a_*)
 
}