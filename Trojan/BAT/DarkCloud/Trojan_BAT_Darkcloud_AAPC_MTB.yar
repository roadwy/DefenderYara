
rule Trojan_BAT_Darkcloud_AAPC_MTB{
	meta:
		description = "Trojan:BAT/Darkcloud.AAPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 05 73 ?? 00 00 0a 0b 07 11 04 11 05 6f ?? 00 00 0a 13 06 73 ?? 00 00 0a 0a 03 75 ?? 00 00 1b 73 ?? 00 00 0a 0c 08 11 06 16 73 ?? 00 00 0a 0d 09 06 6f ?? 00 00 0a 73 ?? 02 00 06 06 6f ?? 00 00 0a 28 ?? 02 00 06 de 1c 09 6f ?? 00 00 0a dc } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}