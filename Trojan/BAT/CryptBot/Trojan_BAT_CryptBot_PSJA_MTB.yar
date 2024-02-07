
rule Trojan_BAT_CryptBot_PSJA_MTB{
	meta:
		description = "Trojan:BAT/CryptBot.PSJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 65 76 65 6e 6f 6c 41 72 61 63 65 61 65 } //01 00  cevenolAraceae
		$a_01_1 = {69 6e 66 65 73 74 73 41 72 61 63 65 61 65 } //01 00  infestsAraceae
		$a_01_2 = {52 65 61 64 41 73 79 6e 63 45 55 43 4a 50 45 6e 63 6f 64 69 6e 67 } //01 00  ReadAsyncEUCJPEncoding
		$a_01_3 = {6c 61 74 41 72 61 63 65 61 65 } //01 00  latAraceae
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {53 6b 69 70 56 65 72 69 66 69 63 61 74 69 6f 6e } //01 00  SkipVerification
		$a_01_6 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //00 00  SymmetricAlgorithm
	condition:
		any of ($a_*)
 
}