
rule Trojan_Win64_BumbleBee_SAS_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c2 24 01 f6 d8 1b c9 d1 ea 23 ce 41 90 01 06 33 ca 41 90 01 06 49 90 01 03 75 90 00 } //01 00 
		$a_03_1 = {8b c2 24 01 f6 d8 1b c9 d1 ea 23 ce 41 90 01 06 33 ca 41 90 01 06 45 90 01 02 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}