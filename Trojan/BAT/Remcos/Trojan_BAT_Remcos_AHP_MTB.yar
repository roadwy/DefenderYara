
rule Trojan_BAT_Remcos_AHP_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 20 06 6f 90 01 03 0a 13 06 11 04 08 02 11 06 18 5a 18 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}