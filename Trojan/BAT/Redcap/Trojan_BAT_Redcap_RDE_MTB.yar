
rule Trojan_BAT_Redcap_RDE_MTB{
	meta:
		description = "Trojan:BAT/Redcap.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 08 91 08 11 08 8f 1d 00 00 01 25 47 11 07 61 d2 52 13 07 11 08 17 58 13 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}