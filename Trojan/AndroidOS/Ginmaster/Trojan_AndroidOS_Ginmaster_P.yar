
rule Trojan_AndroidOS_Ginmaster_P{
	meta:
		description = "Trojan:AndroidOS/Ginmaster.P,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 72 72 79 3a 20 4f 6e 65 20 6c 65 76 65 6c 20 2d 20 6f 6e 65 20 74 61 70 2e 2e } //01 00  Sorry: One level - one tap..
		$a_01_1 = {5b 4d 4b 4c 57 55 5d 47 59 48 48 47 51 5c } //00 00  [MKLWU]GYHHGQ\
	condition:
		any of ($a_*)
 
}