
rule Trojan_BAT_Amadey_SPBX_MTB{
	meta:
		description = "Trojan:BAT/Amadey.SPBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 09 6f ?? 00 00 0a 11 04 08 6f ?? 00 00 0a 11 04 17 6f ?? 00 00 0a 73 ?? 00 00 0a 13 05 11 05 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 06 11 06 07 1f 30 07 8e 69 1f 30 59 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 03 11 05 6f ?? 00 00 0a 28 ?? 00 00 0a de 0c 11 06 2c 07 11 06 6f ?? 00 00 0a dc } //4
		$a_00_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*1) >=5
 
}