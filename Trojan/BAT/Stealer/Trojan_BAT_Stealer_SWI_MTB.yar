
rule Trojan_BAT_Stealer_SWI_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SWI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 72 1a 0a 00 70 28 87 00 00 0a 09 72 ?? ?? ?? 70 6f 4b 01 00 0a 28 4c 01 00 0a 11 04 72 88 0a 00 70 28 87 00 00 0a 09 72 ?? ?? ?? 70 6f 4b 01 00 0a 28 4c 01 00 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}