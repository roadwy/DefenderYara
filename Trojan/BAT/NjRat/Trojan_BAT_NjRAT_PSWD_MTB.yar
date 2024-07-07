
rule Trojan_BAT_NjRAT_PSWD_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PSWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 20 06 00 00 00 38 32 00 00 00 38 8a 00 00 00 7e 0c 00 00 04 07 09 16 6f 90 01 01 00 00 0a 13 04 12 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 38 32 00 00 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}