
rule Trojan_BAT_Bladabindi_ABL_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 09 07 91 06 07 06 08 8c 40 00 00 01 80 01 00 00 04 8e 69 5d 91 07 08 d6 20 68 d6 5d 31 80 10 00 00 04 06 8e 69 d6 14 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}