
rule Trojan_BAT_AsyncRAT_PSTH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PSTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 5d 00 00 70 0a 06 28 56 00 00 0a 25 26 0b 28 4e 00 00 0a 25 26 07 16 07 8e 69 6f 51 01 00 0a 25 26 0a 28 b5 00 00 0a 25 26 } //00 00 
	condition:
		any of ($a_*)
 
}