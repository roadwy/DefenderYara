
rule Trojan_BAT_Zusy_NRC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 09 9a 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 11 04 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 05 } //2
		$a_03_1 = {4a 00 00 0a 74 37 00 00 01 13 06 07 11 06 6f ?? 00 00 0a 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 3a d9 ff ff ff } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}