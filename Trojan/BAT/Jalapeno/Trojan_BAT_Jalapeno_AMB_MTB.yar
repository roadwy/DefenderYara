
rule Trojan_BAT_Jalapeno_AMB_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 06 07 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 10 00 dd ?? 00 00 00 11 05 39 ?? 00 00 00 11 05 6f ?? 00 00 0a dc 11 04 39 } //4
		$a_80_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
	condition:
		((#a_03_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}