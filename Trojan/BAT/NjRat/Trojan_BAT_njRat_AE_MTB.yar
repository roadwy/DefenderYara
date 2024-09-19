
rule Trojan_BAT_njRat_AE_MTB{
	meta:
		description = "Trojan:BAT/njRat.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 00 11 03 11 00 11 01 11 03 59 17 59 91 9c 20 } //3
		$a_01_1 = {59 17 59 11 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}