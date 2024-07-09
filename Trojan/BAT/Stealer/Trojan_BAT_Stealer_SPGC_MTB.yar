
rule Trojan_BAT_Stealer_SPGC_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SPGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {dc 07 18 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 0c 08 06 16 06 8e 69 6f ?? ?? ?? 0a 0d 09 28 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}