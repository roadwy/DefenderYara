
rule Trojan_BAT_Xworm_PGXA_MTB{
	meta:
		description = "Trojan:BAT/Xworm.PGXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 8e b7 1f 50 da 17 da 17 d6 8d 02 00 00 01 0c 16 08 8e b7 17 da 13 13 13 09 2b 1c 08 11 09 02 11 09 1f 50 d6 91 11 07 11 09 11 07 8e b7 5d 91 61 9c 11 09 17 d6 13 09 11 09 11 13 31 de } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}