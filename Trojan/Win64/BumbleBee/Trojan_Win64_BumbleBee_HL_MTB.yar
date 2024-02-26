
rule Trojan_Win64_BumbleBee_HL_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.HL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 88 14 0a ff 40 90 01 01 48 8b 0d 90 01 04 8b 91 90 01 04 2b 90 01 05 8b 48 90 01 01 83 f2 90 01 01 0f af ca 89 48 90 01 01 48 8b 0d 90 01 04 8b 51 90 01 01 2b 90 01 05 81 c2 90 01 04 31 50 90 01 01 48 81 fb 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}