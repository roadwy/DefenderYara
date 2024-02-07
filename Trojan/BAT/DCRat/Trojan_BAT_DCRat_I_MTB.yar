
rule Trojan_BAT_DCRat_I_MTB{
	meta:
		description = "Trojan:BAT/DCRat.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 00 52 00 54 00 41 00 75 00 54 00 47 00 4e 00 54 00 31 00 50 00 77 00 39 00 32 00 5a 00 64 00 74 00 34 00 2e 00 71 00 76 00 36 00 4a 00 6e 00 67 00 42 00 64 00 67 00 78 00 59 00 35 00 34 00 56 00 4a 00 52 00 5a 00 4e 00 } //02 00  BRTAuTGNT1Pw92Zdt4.qv6JngBdgxY54VJRZN
		$a_01_1 = {4f 00 64 00 41 00 32 00 70 00 5a 00 79 00 34 00 65 00 } //01 00  OdA2pZy4e
		$a_01_2 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //01 00  DynamicInvoke
		$a_01_3 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //00 00  CreateDelegate
	condition:
		any of ($a_*)
 
}