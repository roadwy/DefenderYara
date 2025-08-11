
rule Trojan_BAT_PureLogs_SB_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 0c 00 00 06 13 04 11 04 73 05 00 00 0a 13 05 11 05 08 16 73 06 00 00 0a 13 06 11 06 09 6f 07 00 00 0a 09 13 07 dd 3c 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_PureLogs_SB_MTB_2{
	meta:
		description = "Trojan:BAT/PureLogs.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 01 11 05 16 11 06 6f 0d 00 00 0a 38 0a 00 00 00 38 05 00 00 00 38 e5 ff ff ff 11 04 11 05 16 11 05 8e 69 6f 0e 00 00 0a 25 13 06 16 3d ce ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}