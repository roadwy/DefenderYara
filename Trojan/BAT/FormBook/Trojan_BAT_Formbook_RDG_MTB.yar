
rule Trojan_BAT_Formbook_RDG_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 31 36 64 31 64 36 61 2d 33 33 31 65 2d 34 38 32 38 2d 62 61 31 34 2d 32 61 31 36 35 36 62 31 61 64 37 38 } //1 016d1d6a-331e-4828-ba14-2a1656b1ad78
		$a_01_1 = {44 48 46 48 44 46 48 44 48 48 44 46 } //1 DHFHDFHDHHDF
		$a_01_2 = {09 11 0b 8f 2e 00 00 01 25 4b 11 0c 61 54 11 0d } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}