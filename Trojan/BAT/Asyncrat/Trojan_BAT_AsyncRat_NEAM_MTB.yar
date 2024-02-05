
rule Trojan_BAT_AsyncRat_NEAM_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {00 00 70 1f 2d 28 28 00 00 06 28 12 00 00 0a 02 18 16 8d 01 00 00 01 28 13 00 00 0a 0a 20 66 08 00 00 28 14 00 00 0a 06 2a } //05 00 
		$a_01_1 = {49 00 6e 00 2b 00 76 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 6f 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 2b 00 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}