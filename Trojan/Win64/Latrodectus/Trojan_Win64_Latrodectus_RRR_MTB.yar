
rule Trojan_Win64_Latrodectus_RRR_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.RRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 f7 f1 c5 ed fd e2 c5 f5 fd f9 c5 e5 fd c3 45 8a 14 10 c5 cd 68 f1 c5 c5 60 c1 c5 c5 68 f9 c5 cd fd eb c5 dd fd d3 c5 c5 fd cb 44 30 14 0f c5 c5 71 d7 08 c5 fd 6f c8 c5 fd 6f da c5 fd 6f ec 48 ff c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}