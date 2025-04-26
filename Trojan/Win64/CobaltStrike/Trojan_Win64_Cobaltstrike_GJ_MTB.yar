
rule Trojan_Win64_Cobaltstrike_GJ_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 45 e8 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 49 89 c0 ba 00 00 00 00 b9 00 00 00 00 48 8b 05 19 6a 00 00 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}