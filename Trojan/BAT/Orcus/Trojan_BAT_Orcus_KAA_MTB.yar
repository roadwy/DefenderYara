
rule Trojan_BAT_Orcus_KAA_MTB{
	meta:
		description = "Trojan:BAT/Orcus.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 08 18 5b 02 08 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 08 18 58 0c 08 06 32 e4 90 00 } //05 00 
		$a_01_1 = {36 00 34 00 38 00 36 00 2e 00 32 00 2e 00 2e 00 46 00 36 00 35 00 32 00 2e 00 32 00 41 00 37 } //00 00 
	condition:
		any of ($a_*)
 
}