
rule Trojan_BAT_Stealc_EAJY_MTB{
	meta:
		description = "Trojan:BAT/Stealc.EAJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 11 04 07 6f 29 00 00 0a 17 59 6f 2a 00 00 0a 6f 2b 00 00 0a 6f 2c 00 00 0a 26 11 05 17 58 13 05 11 05 02 32 d9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}