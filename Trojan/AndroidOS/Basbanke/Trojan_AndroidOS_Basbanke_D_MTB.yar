
rule Trojan_AndroidOS_Basbanke_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Basbanke.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6d 73 73 65 6e 64 65 72 74 65 73 74 } //01 00  smssendertest
		$a_01_1 = {69 66 61 64 2f 6e 72 61 79 61 6e 70 2f 69 72 } //01 00  ifad/nrayanp/ir
		$a_01_2 = {43 75 72 72 65 6e 74 43 6f 75 6e 74 72 79 } //01 00  CurrentCountry
		$a_01_3 = {46 69 6e 64 42 79 4d 61 69 6c } //00 00  FindByMail
	condition:
		any of ($a_*)
 
}