
rule Trojan_BAT_Convagent_SPP_MTB{
	meta:
		description = "Trojan:BAT/Convagent.SPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 8d 01 00 00 01 13 07 11 07 16 02 a2 11 07 0d 07 14 09 6f ?? ?? ?? 0a 13 04 11 04 14 fe 01 13 06 11 06 38 05 00 00 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}