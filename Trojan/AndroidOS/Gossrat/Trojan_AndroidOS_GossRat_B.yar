
rule Trojan_AndroidOS_GossRat_B{
	meta:
		description = "Trojan:AndroidOS/GossRat.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 5f 49 73 5f 54 68 65 5f 56 56 61 79 } //02 00  This_Is_The_VVay
		$a_01_1 = {74 65 73 74 68 61 64 69 72 61 74 74 65 73 74 2f 53 65 72 76 69 63 65 52 65 61 64 } //00 00  testhadirattest/ServiceRead
	condition:
		any of ($a_*)
 
}