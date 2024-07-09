
rule Trojan_BAT_Remcos_SPJJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SPJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 18 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0c de 19 07 2c 06 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}