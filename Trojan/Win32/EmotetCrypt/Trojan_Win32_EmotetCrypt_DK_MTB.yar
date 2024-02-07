
rule Trojan_Win32_EmotetCrypt_DK_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c2 33 d2 f7 35 90 01 04 89 55 f8 8b 45 08 03 45 ec 33 c9 8a 08 8b 55 fc 03 55 f8 33 c0 8a 02 33 c8 8b 55 18 03 55 ec 88 0a 90 00 } //01 00 
		$a_81_1 = {64 57 79 44 49 68 51 28 2a 66 53 65 6f 72 65 44 57 74 39 44 26 45 2b 38 74 65 55 54 73 61 77 25 40 49 40 37 47 39 2b 33 4f 42 30 58 30 4a 73 63 41 42 4c 4f } //01 00  dWyDIhQ(*fSeoreDWt9D&E+8teUTsaw%@I@7G9+3OB0X0JscABLO
		$a_01_2 = {57 57 ff d6 57 57 ff d6 8b 45 e8 8a 0c 18 02 4d ff 8b 45 f0 8b 55 e4 32 0c 02 88 08 40 ff 4d 0c 89 45 f0 0f 85 } //01 00 
		$a_81_3 = {72 4b 30 50 2b 58 58 25 40 59 61 70 39 63 64 72 29 48 79 56 3c 76 65 37 71 4b 36 2b 42 45 57 68 51 3e 5e 41 59 70 32 61 74 4a 23 4e 4c 6a 73 7a 55 6c 4c 40 63 64 6c 45 53 5f 6f 54 6e 44 4e 77 64 6d } //00 00  rK0P+XX%@Yap9cdr)HyV<ve7qK6+BEWhQ>^AYp2atJ#NLjszUlL@cdlES_oTnDNwdm
	condition:
		any of ($a_*)
 
}