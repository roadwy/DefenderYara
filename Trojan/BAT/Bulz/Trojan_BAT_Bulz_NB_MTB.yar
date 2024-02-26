
rule Trojan_BAT_Bulz_NB_MTB{
	meta:
		description = "Trojan:BAT/Bulz.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {7e 37 01 00 04 02 28 90 01 02 00 06 28 90 01 02 00 0a 72 90 01 02 00 70 6f 90 01 02 00 0a 6f 90 01 02 00 06 26 02 16 90 00 } //01 00 
		$a_01_1 = {56 61 6e 69 6c 6c 61 52 61 74 2e 65 78 65 } //00 00  VanillaRat.exe
	condition:
		any of ($a_*)
 
}