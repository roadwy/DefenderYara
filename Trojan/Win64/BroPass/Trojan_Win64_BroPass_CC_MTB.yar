
rule Trojan_Win64_BroPass_CC_MTB{
	meta:
		description = "Trojan:Win64/BroPass.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 b9 40 00 00 00 41 b8 00 30 00 00 8b d7 33 c9 48 8b f0 8b df ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}