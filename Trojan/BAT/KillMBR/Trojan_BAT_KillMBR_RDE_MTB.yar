
rule Trojan_BAT_KillMBR_RDE_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 09 08 28 17 00 00 0a 0d 00 11 04 17 58 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}