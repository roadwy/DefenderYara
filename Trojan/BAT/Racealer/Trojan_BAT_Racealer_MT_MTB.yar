
rule Trojan_BAT_Racealer_MT_MTB{
	meta:
		description = "Trojan:BAT/Racealer.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {2c 0b 06 6f 90 02 04 28 90 02 04 2a 90 09 32 00 02 28 90 02 04 73 90 02 04 0a 28 90 02 04 14 fe 90 02 05 73 90 02 04 6f 90 02 04 06 6f 90 02 04 7e 90 02 04 28 90 00 } //01 00 
		$a_81_1 = {5f 50 65 78 65 73 6f 47 6f } //01 00  _PexesoGo
		$a_81_2 = {5f 50 65 78 65 73 6f 57 61 69 74 } //00 00  _PexesoWait
	condition:
		any of ($a_*)
 
}