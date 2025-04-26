
rule Trojan_BAT_Marsilia_KAF_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 02 08 93 06 08 06 8e 69 5d 93 61 d1 9d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}