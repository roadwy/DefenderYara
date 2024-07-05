
rule Trojan_Win64_Dacic_RR_MTB{
	meta:
		description = "Trojan:Win64/Dacic.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b c8 ff 15 90 01 04 48 8b 5d 90 01 01 48 2b 5d 90 01 01 48 c1 fb 05 ff 15 90 01 04 48 98 33 d2 48 f7 f3 48 63 d2 48 c1 e2 05 48 03 55 90 01 01 48 8d 8d 90 01 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}