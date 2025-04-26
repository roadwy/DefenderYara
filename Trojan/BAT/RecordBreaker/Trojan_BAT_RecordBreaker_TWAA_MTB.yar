
rule Trojan_BAT_RecordBreaker_TWAA_MTB{
	meta:
		description = "Trojan:BAT/RecordBreaker.TWAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 72 01 00 00 70 28 ?? 00 00 06 72 33 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 13 0b } //2
		$a_03_1 = {09 11 0a 28 ?? 00 00 2b 16 11 0a 28 ?? 00 00 2b 8e 69 6f ?? 00 00 0a 16 } //2
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}