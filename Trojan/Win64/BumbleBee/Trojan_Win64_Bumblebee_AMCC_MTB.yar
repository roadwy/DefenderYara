
rule Trojan_Win64_Bumblebee_AMCC_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.AMCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 60 8b 44 24 40 35 90 01 04 89 44 24 5c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}