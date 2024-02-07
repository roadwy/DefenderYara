
rule Trojan_AndroidOS_Drinik_A{
	meta:
		description = "Trojan:AndroidOS/Drinik.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 68 75 6a 78 78 6c 6c 69 66 } //02 00  chujxxllif
		$a_00_1 = {65 61 6f 6f 6d 78 68 6c 74 69 66 } //01 00  eaoomxhltif
		$a_00_2 = {7a 7a 63 78 76 75 64 64 69 } //01 00  zzcxvuddi
		$a_00_3 = {62 6a 6f 6d 78 61 6c 6b 6c } //00 00  bjomxalkl
	condition:
		any of ($a_*)
 
}