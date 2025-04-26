
rule Trojan_Win64_Tedy_QC_MTB{
	meta:
		description = "Trojan:Win64/Tedy.QC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 44 8b d3 41 be bf e5 f1 78 48 8b 50 18 48 83 c2 10 48 8b 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}