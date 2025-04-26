
rule Trojan_BAT_NanoBot_ASCN_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.ASCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f ?? 00 00 0a 17 59 fe 01 13 05 11 05 2c 04 16 0d 2b 04 09 17 58 0d 00 11 04 17 58 13 04 11 04 02 8e 69 fe 04 13 06 11 06 2d c3 } //1
		$a_81_1 = {47 65 6f 6d 65 74 72 69 5f 4f 64 65 76 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Geometri_Odev.Properties.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}