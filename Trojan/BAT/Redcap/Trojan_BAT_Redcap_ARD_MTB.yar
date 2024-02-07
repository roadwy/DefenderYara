
rule Trojan_BAT_Redcap_ARD_MTB{
	meta:
		description = "Trojan:BAT/Redcap.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 04 16 13 05 2b 30 11 04 11 05 9a 13 06 00 11 06 72 bd 02 00 70 6f 90 01 03 0a 13 07 11 07 13 08 11 08 2c 0b 00 06 11 06 6f 90 01 03 0a 00 00 00 11 05 17 58 13 05 11 05 11 04 8e 69 32 c8 90 00 } //01 00 
		$a_01_1 = {48 00 62 00 6f 00 4d 00 61 00 78 00 32 00 2e 00 30 00 2e 00 65 00 78 00 65 00 } //00 00  HboMax2.0.exe
	condition:
		any of ($a_*)
 
}