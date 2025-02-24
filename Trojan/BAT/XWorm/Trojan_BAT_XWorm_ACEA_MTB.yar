
rule Trojan_BAT_XWorm_ACEA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ACEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 72 15 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 72 47 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0c dd 10 00 00 00 07 39 06 00 00 00 07 6f ?? 00 00 0a dc } //3
		$a_00_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_00_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=5
 
}