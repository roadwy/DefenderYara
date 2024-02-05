
rule Trojan_BAT_Hawkeye_AHE_MTB{
	meta:
		description = "Trojan:BAT/Hawkeye.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0b 2b 20 09 65 1a 5d 2c 11 28 90 01 03 06 8e 69 1b 59 17 58 8d 05 00 00 01 0c 09 17 58 0d 09 1f 64 31 c1 90 00 } //01 00 
		$a_01_1 = {73 00 6f 00 63 00 72 00 75 00 41 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}