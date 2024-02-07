
rule Trojan_Win64_BumbleBee_PACD_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.PACD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 06 00 "
		
	strings :
		$a_03_0 = {43 8a 0c 0c 2a 8c 24 90 01 04 32 8c 24 90 01 04 49 8b 42 90 01 01 41 88 0c 01 83 fe 90 01 01 0f 84 90 01 04 49 8b 52 90 01 01 8b ce b8 90 01 04 44 8b ee d2 e0 fe c8 41 8a 0c 11 49 8b 92 90 01 04 22 c8 88 4c 24 90 01 01 48 8b c5 90 00 } //01 00 
		$a_01_1 = {43 67 4b 36 32 } //01 00  CgK62
		$a_01_2 = {4c 76 71 4b 4d 6e 36 39 38 } //01 00  LvqKMn698
		$a_01_3 = {4f 44 49 56 4e 31 41 64 34 } //01 00  ODIVN1Ad4
		$a_01_4 = {54 6e 63 67 48 43 38 37 36 58 59 33 } //01 00  TncgHC876XY3
		$a_01_5 = {55 51 72 41 41 61 37 31 35 53 70 38 } //01 00  UQrAAa715Sp8
		$a_01_6 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}