
rule Trojan_BAT_Remcos_IDN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.IDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 03 11 06 91 07 11 06 07 8e 69 5d 91 61 08 61 d2 6f 90 01 03 0a 00 00 11 06 17 58 90 00 } //01 00 
		$a_01_1 = {44 00 53 00 41 00 46 00 53 00 41 00 46 00 53 00 41 00 46 00 53 00 46 00 53 00 41 00 46 00 53 00 41 00 46 00 53 00 41 00 46 00 53 00 46 00 53 00 41 00 } //01 00 
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}