
rule Trojan_Win64_CobaltStrike_SHC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 44 24 48 48 8b 7c 24 48 48 8b 74 24 40 48 8b 4c 24 30 f3 a4 ff 54 24 48 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}