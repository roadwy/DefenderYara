
rule Trojan_BAT_Jalapeno_ZHA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.ZHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 17 58 0a 08 07 6f ?? 00 00 0a 06 17 58 0a 73 ?? 00 00 0a 0d 06 17 58 0a 09 08 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 06 17 58 0a 11 04 02 1f 10 02 8e 69 1f 10 59 6f ?? 00 00 0a 06 17 58 0a 11 04 } //10
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}