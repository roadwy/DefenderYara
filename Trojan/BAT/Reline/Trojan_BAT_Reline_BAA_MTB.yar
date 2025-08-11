
rule Trojan_BAT_Reline_BAA_MTB{
	meta:
		description = "Trojan:BAT/Reline.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 06 11 04 91 07 11 04 09 5d ?? ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 06 8e 69 32 df } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}