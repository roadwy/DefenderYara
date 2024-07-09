
rule Trojan_BAT_Marsilia_SPFV_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.SPFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 91 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 07 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 8e 69 5d 91 61 d2 9c 07 17 58 0b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}