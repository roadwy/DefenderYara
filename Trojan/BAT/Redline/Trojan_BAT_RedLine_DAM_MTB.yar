
rule Trojan_BAT_RedLine_DAM_MTB{
	meta:
		description = "Trojan:BAT/RedLine.DAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 1e 09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? 00 00 0a 11 04 13 05 11 05 17 58 13 04 11 04 07 8e 69 32 db } //4
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}