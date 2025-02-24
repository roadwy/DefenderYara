
rule Trojan_Win64_Latrodectus_ASL_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 8a 14 10 c5 cd 68 f1 c5 c5 60 c1 c5 c5 68 f9 c5 cd fd eb c5 dd fd d3 c5 c5 fd cb 44 30 14 0f c5 c5 71 d7 08 c5 fd 6f c8 c5 fd 6f da c5 fd 6f ec 48 ff c1 c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd 48 89 c8 90 48 81 f9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}