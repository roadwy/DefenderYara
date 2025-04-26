
rule Trojan_BAT_Stealer_SPCO_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SPCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 05 16 73 ?? ?? ?? 0a 13 08 11 08 11 06 6f ?? ?? ?? 0a 11 06 6f ?? ?? ?? 0a 0b dd 2d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}