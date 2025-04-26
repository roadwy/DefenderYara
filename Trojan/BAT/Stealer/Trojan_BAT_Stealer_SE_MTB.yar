
rule Trojan_BAT_Stealer_SE_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {7b 06 00 00 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 07 06 7b 07 00 00 04 28 ?? ?? ?? 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}