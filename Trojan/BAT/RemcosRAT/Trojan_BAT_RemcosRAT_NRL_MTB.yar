
rule Trojan_BAT_RemcosRAT_NRL_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 1f 00 00 0a 72 90 01 02 00 70 28 90 01 02 00 06 6f 90 01 02 00 0a 28 90 01 02 00 0a 13 01 38 90 01 02 00 00 11 01 16 11 01 8e 69 28 90 01 02 00 06 38 90 01 02 00 00 11 01 13 02 38 90 01 02 00 00 dd 90 01 02 00 00 90 00 } //05 00 
		$a_03_1 = {02 28 19 00 00 0a 74 90 01 02 00 01 6f 90 01 02 00 0a 73 90 01 02 00 0a 13 00 6f 90 01 02 00 0a 11 00 6f 90 01 02 00 0a 38 90 01 02 00 00 11 00 6f 90 01 02 00 0a 2a 90 00 } //01 00 
		$a_01_2 = {4a 00 67 00 65 00 6e 00 74 00 69 00 64 00 6b 00 72 00 } //00 00  Jgentidkr
	condition:
		any of ($a_*)
 
}