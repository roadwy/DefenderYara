
rule Ransom_Win32_Blacksuit_AD_MTB{
	meta:
		description = "Ransom:Win32/Blacksuit.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 01 2d 01 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //64 00 
		$a_03_1 = {8b c6 8d 0c 37 33 d2 46 f7 74 24 90 01 01 8a 82 90 01 04 32 04 0b 88 01 81 fe 90 01 02 00 00 72 90 00 } //64 00 
		$a_01_2 = {72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 62 00 6c 00 61 00 63 00 6b 00 73 00 75 00 69 00 74 00 2e 00 74 00 78 00 74 00 } //64 00  readme.blacksuit.txt
		$a_01_3 = {42 45 47 49 4e 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 } //00 00  BEGIN RSA PUBLIC KEY
		$a_01_4 = {5d 04 00 00 37 48 06 80 5c 2b 00 00 38 48 06 80 00 00 01 00 08 00 15 00 ac 21 50 61 63 6b 49 6e 6a 65 63 74 6f 72 2e 4d 42 21 4d 54 } //42 00 
	condition:
		any of ($a_*)
 
}