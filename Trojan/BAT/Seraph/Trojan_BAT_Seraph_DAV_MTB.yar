
rule Trojan_BAT_Seraph_DAV_MTB{
	meta:
		description = "Trojan:BAT/Seraph.DAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 08 11 04 6f ?? 00 00 0a 13 05 06 11 05 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 28 ?? 00 00 06 0d 06 6f ?? 00 00 0a 09 16 09 8e 69 6f ?? 00 00 0a 13 06 de 2e } //3
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}