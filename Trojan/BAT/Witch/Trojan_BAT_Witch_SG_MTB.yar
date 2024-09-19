
rule Trojan_BAT_Witch_SG_MTB{
	meta:
		description = "Trojan:BAT/Witch.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 30 6f 0b 00 00 0a 28 03 00 00 06 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}