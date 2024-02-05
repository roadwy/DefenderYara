
rule Trojan_BAT_AsyncRat_NEAH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2b 00 06 1e 2e 14 2b 18 03 04 5d 0c 2b 16 03 04 5a 0c 2b 10 03 04 61 0c 2b 0a 03 04 58 0c 2b 04 03 0c 2b 00 08 2a } //00 00 
	condition:
		any of ($a_*)
 
}