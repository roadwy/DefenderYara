
rule Trojan_Win64_BumbleBee_SAL_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 01 49 ff 82 90 01 04 49 90 01 06 48 90 01 06 49 33 c1 48 90 01 06 49 90 01 06 48 69 81 90 01 08 48 90 01 06 49 90 01 03 49 90 01 02 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}