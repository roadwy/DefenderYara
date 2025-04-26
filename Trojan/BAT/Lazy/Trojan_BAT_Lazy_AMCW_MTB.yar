
rule Trojan_BAT_Lazy_AMCW_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AMCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 09 11 05 02 11 05 91 08 61 07 06 91 61 b4 9c } //3
		$a_01_1 = {09 02 8e 69 18 da 17 d6 } //1
		$a_03_2 = {70 20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 08 a2 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=5
 
}