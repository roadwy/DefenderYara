
rule Trojan_BAT_Coins_AAQR_MTB{
	meta:
		description = "Trojan:BAT/Coins.AAQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 16 07 1f 0f 1f 10 28 ?? 01 00 06 7e ?? 00 00 04 06 07 28 ?? 01 00 06 7e ?? 00 00 04 06 18 28 ?? 01 00 06 7e ?? 00 00 04 06 19 28 ?? 01 00 06 7e ?? 00 00 04 06 28 ?? 01 00 06 0d 7e ?? 00 00 04 09 03 16 03 8e 69 28 ?? 01 00 06 2a } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}