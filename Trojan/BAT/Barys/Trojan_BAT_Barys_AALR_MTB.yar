
rule Trojan_BAT_Barys_AALR_MTB{
	meta:
		description = "Trojan:BAT/Barys.AALR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {17 11 0a 11 09 28 ?? 00 00 06 13 0b 11 0b 02 1a 02 8e 69 1a 59 6f ?? 01 00 0a 28 ?? 00 00 06 0b de 2d 11 0b 2c 07 11 0b 6f ?? 00 00 0a dc } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}