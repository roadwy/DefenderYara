
rule Trojan_AndroidOS_Anubis_A{
	meta:
		description = "Trojan:AndroidOS/Anubis.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 69 73 69 74 5f 62 6c 61 63 6b 5f 64 65 6c } //01 00  visit_black_del
		$a_01_1 = {43 70 75 46 65 61 74 75 72 65 } //01 00  CpuFeature
		$a_01_2 = {43 61 6e 27 74 20 6e 6f 74 20 66 69 6e 69 73 68 20 72 65 63 6f 72 64 69 6e 67 } //01 00  Can't not finish recording
		$a_01_3 = {43 6f 6e 6e 65 63 74 20 63 6c 69 70 20 66 69 6c 65 73 20 66 61 69 6c 65 64 } //00 00  Connect clip files failed
	condition:
		any of ($a_*)
 
}