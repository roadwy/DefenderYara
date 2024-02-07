
rule Trojan_Win32_Emotetcrypt_GA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c1 2b 05 90 01 04 8b 4d 08 0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 8b 45 f4 2b 05 90 01 04 03 05 90 01 04 2b 05 90 01 04 03 05 90 01 04 2b 05 90 01 04 03 05 90 01 04 8b 4d 0c 88 14 01 e9 90 00 } //01 00 
		$a_81_1 = {63 24 26 58 4b 54 53 32 66 43 7a 77 53 40 71 76 4a 24 45 71 64 49 63 53 4d 38 37 6a 33 38 56 62 45 56 31 2b 39 3c 4e 44 4f 37 29 58 59 6a 41 53 54 76 3e 73 54 5e 4c 55 25 5a 32 25 58 3f 5f 42 6d 56 43 51 47 79 26 52 45 4c } //00 00  c$&XKTS2fCzwS@qvJ$EqdIcSM87j38VbEV1+9<NDO7)XYjASTv>sT^LU%Z2%X?_BmVCQGy&REL
	condition:
		any of ($a_*)
 
}