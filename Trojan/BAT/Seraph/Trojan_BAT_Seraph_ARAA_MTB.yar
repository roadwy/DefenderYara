
rule Trojan_BAT_Seraph_ARAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.ARAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 8e 69 17 59 0d 38 ?? 00 00 00 07 08 06 09 91 9c 08 17 58 0c 09 17 59 0d 09 16 2f ee } //4
		$a_01_1 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 GetByteArrayAsync
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}