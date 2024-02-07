
rule Trojan_AndroidOS_Meftadon_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Meftadon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 78 78 78 78 78 2e 7a 7a 7a 7a 7a 7a 2e 67 6c 75 65 2e 41 63 74 69 76 69 74 79 4d 6f 64 75 6c 65 53 74 61 72 74 } //01 00  xxxxxx.zzzzzz.glue.ActivityModuleStart
		$a_01_1 = {6e 65 65 64 5f 6b 6e 6f 63 6b } //01 00  need_knock
		$a_01_2 = {74 74 70 2f 2f 62 69 62 6f 6e 61 64 6f 2e 63 6f 6d } //01 00  ttp//bibonado.com
		$a_01_3 = {6d 65 74 61 66 6f 6e 64 } //00 00  metafond
	condition:
		any of ($a_*)
 
}