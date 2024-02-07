
rule Trojan_Win32_Emotetcrypt_HF_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 14 1a 03 c2 99 bb 90 01 04 f7 fb a1 90 01 04 8b da 8b 15 90 01 04 03 5c 24 90 01 01 8b ea 2b ee 03 e9 8d 74 28 ff 0f af 35 90 01 04 8d 68 01 0f af e8 2b 6c 24 20 2b ef 2b e9 8d 04 6e 2b c2 2b c1 8d 04 40 0f b6 0c 18 8b 44 24 24 30 08 90 00 } //01 00 
		$a_81_1 = {6d 55 25 49 70 59 7a 59 4a 3c 63 68 65 65 33 34 50 74 30 6c 4c 77 65 4e 63 21 75 21 52 56 7a 45 42 45 47 70 28 78 38 2a 65 69 6c 51 3c 68 71 75 63 30 39 72 31 41 68 3e 49 77 4f 72 57 51 5f 47 36 67 75 28 33 63 40 36 79 4d 23 6c 49 42 52 6c 4a 74 4c 47 61 79 21 5a 40 77 26 58 54 53 79 36 32 36 74 } //00 00  mU%IpYzYJ<chee34Pt0lLweNc!u!RVzEBEGp(x8*eilQ<hquc09r1Ah>IwOrWQ_G6gu(3c@6yM#lIBRlJtLGay!Z@w&XTSy626t
	condition:
		any of ($a_*)
 
}