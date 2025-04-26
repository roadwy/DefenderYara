
rule Trojan_BAT_NjRat_AAQV_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AAQV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 11 11 0f 73 ?? 00 00 0a 11 11 07 11 0c 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 0b 1a 8d ?? 00 00 01 13 0e 11 0b 11 0e 16 1a 6f ?? 00 00 0a 26 11 0e 16 28 ?? 00 00 0a 13 08 73 ?? 00 00 06 13 0a 1b 8d ?? 00 00 01 13 04 11 0b 11 04 16 1b 6f ?? 00 00 0a 26 11 0a 11 04 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}