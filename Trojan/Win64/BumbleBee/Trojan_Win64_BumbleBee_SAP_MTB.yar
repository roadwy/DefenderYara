
rule Trojan_Win64_BumbleBee_SAP_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 2b c0 44 90 01 06 2d 90 01 04 31 43 90 01 01 8d 82 90 01 04 44 90 01 03 ff 43 90 01 01 0f af c8 41 90 01 06 89 4b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}