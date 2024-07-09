
rule Trojan_BAT_Stealer_SSXP_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SSXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 30 06 73 ?? ?? ?? 0a 7a 03 28 ?? ?? ?? 0a 0a 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 06 16 06 8e 69 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}