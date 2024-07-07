
rule Trojan_BAT_Marsilia_AMCC_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 0f 11 11 11 12 61 11 13 11 0d 5d 59 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}