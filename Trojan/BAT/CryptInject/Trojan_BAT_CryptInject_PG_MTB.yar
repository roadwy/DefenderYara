
rule Trojan_BAT_CryptInject_PG_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 8f 21 00 00 01 25 71 21 00 00 01 07 11 04 91 61 d2 81 21 00 00 01 02 7b ?? 00 00 04 08 11 04 } //1
		$a_01_1 = {08 11 04 8f 21 00 00 01 25 71 21 00 00 01 08 11 04 91 61 d2 81 21 00 00 01 11 04 } //1
		$a_01_2 = {58 13 04 11 04 07 8e 69 32 ae } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}