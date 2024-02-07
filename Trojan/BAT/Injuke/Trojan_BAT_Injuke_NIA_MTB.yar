
rule Trojan_BAT_Injuke_NIA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.NIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {6f 22 01 00 0a 6f 90 01 02 00 0a a2 25 18 73 90 01 02 00 0a 06 1e 06 6f 90 01 02 00 0a 1e da 6f 90 01 02 00 0a 28 90 01 02 00 0a 90 00 } //01 00 
		$a_01_1 = {33 00 52 00 47 00 4b 00 68 00 37 00 70 00 } //00 00  3RGKh7p
	condition:
		any of ($a_*)
 
}