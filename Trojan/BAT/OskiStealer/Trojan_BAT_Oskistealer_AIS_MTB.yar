
rule Trojan_BAT_Oskistealer_AIS_MTB{
	meta:
		description = "Trojan:BAT/Oskistealer.AIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 0a 18 0b 06 6f 90 01 01 00 00 0a 07 9a 0c 08 6f 90 01 01 00 00 0a 07 17 58 25 0b 9a 0d 09 14 02 28 90 00 } //01 00 
		$a_01_1 = {4d 00 6f 00 6e 00 6f 00 70 00 6f 00 6c 00 79 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 6f 00 72 00 } //00 00  MonopolySimulator
	condition:
		any of ($a_*)
 
}