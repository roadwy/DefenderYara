
rule Trojan_BAT_Genpacker_A{
	meta:
		description = "Trojan:BAT/Genpacker.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 07 25 17 58 0b 61 d2 0d 25 1e 63 07 25 17 58 0b 61 d2 13 04 26 11 04 09 13 04 0d 11 04 1e 62 09 60 d1 9d 17 58 } //01 00 
		$a_01_1 = {55 73 62 44 65 74 65 63 74 6f 72 } //00 00  UsbDetector
	condition:
		any of ($a_*)
 
}