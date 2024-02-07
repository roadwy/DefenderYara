
rule Trojan_BAT_Tnega_IKV_MTB{
	meta:
		description = "Trojan:BAT/Tnega.IKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {20 02 08 00 00 28 12 00 00 0a 73 58 00 00 0a 0a 06 72 23 10 00 70 28 7b 00 00 06 6f 59 00 00 0a 2a } //01 00 
		$a_00_1 = {20 d5 07 00 00 28 12 00 00 0a 02 04 28 55 00 00 06 03 17 18 8d 01 00 00 01 0a 06 28 5b 00 00 0a 26 2a } //01 00 
		$a_01_2 = {74 00 65 00 72 00 65 00 72 00 65 00 72 00 65 00 72 00 77 00 67 00 61 00 6d 00 61 00 6c 00 2e 00 74 00 78 00 74 00 } //00 00  tererererwgamal.txt
	condition:
		any of ($a_*)
 
}