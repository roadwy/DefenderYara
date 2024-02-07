
rule Trojan_BAT_Bladabindi_MBJK_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 00 67 00 4e 00 4b 00 5a 00 34 00 49 00 53 00 38 00 4d 00 61 00 4e 00 62 00 70 00 4f 00 65 00 53 00 55 00 75 00 64 00 73 00 53 00 46 00 57 00 71 00 6a 00 6e 00 45 00 6c 00 62 } //01 00 
		$a_01_1 = {66 00 65 00 4f 00 34 00 57 00 46 00 59 00 55 00 52 00 76 00 6d 00 6b 00 74 00 68 00 38 00 74 00 6e 00 62 00 54 00 61 00 52 00 6a 00 4a 00 4f 00 61 00 36 00 4a 00 59 } //01 00 
		$a_01_2 = {20 b8 88 00 00 28 } //01 00 
		$a_01_3 = {73 73 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  sss.Resources
		$a_01_4 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00  MD5CryptoServiceProvider
	condition:
		any of ($a_*)
 
}