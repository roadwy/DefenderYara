
rule Trojan_BAT_NjRat_BCAA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.BCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 16 8c ?? 00 00 01 a2 14 14 28 ?? 00 00 0a 11 0b 17 59 17 58 17 59 17 58 17 59 17 58 8d ?? 00 00 01 13 0c 07 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}