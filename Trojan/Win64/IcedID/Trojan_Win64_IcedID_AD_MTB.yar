
rule Trojan_Win64_IcedID_AD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 83 e2 03 41 83 e0 03 42 8a 4c 85 e0 02 4c 95 e0 32 c1 42 8b 4c 85 e0 41 88 04 1b 83 e1 07 8b 44 95 } //01 00 
		$a_01_1 = {48 8d 45 d7 45 33 c0 48 89 44 24 30 4c 8d 4d 7f 48 8d 45 77 33 c9 48 89 44 24 28 48 8d 55 e7 48 } //01 00 
		$a_01_2 = {39 7c 24 68 75 } //01 00  9|$hu
		$a_01_3 = {4c 24 30 48 6b } //01 00  L$0Hk
		$a_01_4 = {44 24 20 21 4d 58 45 33 } //00 00  D$ !MXE3
	condition:
		any of ($a_*)
 
}