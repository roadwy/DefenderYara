
rule Trojan_BAT_Crysan_AAC_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 1a 00 00 0a 0a 73 1b 00 00 0a 0b 06 16 73 1c 00 00 0a 73 1d 00 00 0a 0c 08 07 6f 1e 00 00 0a 07 6f 1f 00 00 0a 28 01 00 00 2b 28 02 00 00 2b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}