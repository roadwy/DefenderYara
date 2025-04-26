
rule Trojan_BAT_Formbook_NEAI_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NEAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 38 61 31 36 34 36 35 63 2d 35 30 33 37 2d 34 36 65 36 2d 61 63 63 37 2d 30 37 65 34 62 66 62 64 35 64 38 66 } //5 $8a16465c-5037-46e6-acc7-07e4bfbd5d8f
		$a_01_1 = {4a 48 68 47 67 37 36 32 2e 70 64 62 } //2 JHhGg762.pdb
		$a_01_2 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 } //2 Confuser.Core 1.6.0
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}