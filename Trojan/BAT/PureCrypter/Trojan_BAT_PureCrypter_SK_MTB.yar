
rule Trojan_BAT_PureCrypter_SK_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 72 4d 00 00 70 73 06 00 00 0a 6f 07 00 00 0a 6f 08 00 00 0a 13 06 73 04 00 00 0a 13 07 11 06 11 07 6f 09 00 00 0a 11 07 6f 0a 00 00 0a 13 04 dd 0f 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}