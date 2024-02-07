
rule Trojan_BAT_Quasar_NQC_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {20 e6 00 00 00 28 90 01 01 00 00 06 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 28 90 01 01 00 00 06 0b 07 74 90 01 01 00 00 1b 0a 90 00 } //01 00 
		$a_01_1 = {6f 72 74 68 6f 64 6f 78 2e 65 78 65 } //00 00  orthodox.exe
	condition:
		any of ($a_*)
 
}