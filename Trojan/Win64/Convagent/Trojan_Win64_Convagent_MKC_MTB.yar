
rule Trojan_Win64_Convagent_MKC_MTB{
	meta:
		description = "Trojan:Win64/Convagent.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 8b fe 41 8b f6 45 8b ee 41 83 fc 03 41 b8 ff 7f 00 00 0f 94 c0 41 d1 ef c1 ee 02 33 d2 41 c1 ee 03 41 83 e7 01 83 e6 01 89 44 24 74 41 83 e6 01 41 83 e5 01 } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}