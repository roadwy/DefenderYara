
rule Trojan_BAT_Crysan_SSXP_MTB{
	meta:
		description = "Trojan:BAT/Crysan.SSXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 73 10 00 00 0a 0b 00 00 20 00 0c 00 00 28 ?? ?? ?? 0a 00 07 06 72 6e 01 00 70 6f ?? ?? ?? 0a 00 72 6e 01 00 70 28 ?? ?? ?? 0a 26 00 de 05 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}