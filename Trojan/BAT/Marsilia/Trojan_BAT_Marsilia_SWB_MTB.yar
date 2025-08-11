
rule Trojan_BAT_Marsilia_SWB_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.SWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {12 00 12 01 28 07 00 00 06 02 06 07 28 08 00 00 06 51 28 09 00 00 06 0c 03 08 28 0a 00 00 06 51 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}