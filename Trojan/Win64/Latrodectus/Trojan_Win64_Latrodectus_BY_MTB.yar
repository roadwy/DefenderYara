
rule Trojan_Win64_Latrodectus_BY_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 8a 1c 10 c5 e5 75 db c5 e5 71 f3 07 c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff d8 c5 cd 60 e1 c5 cd 68 f1 c5 c5 60 c1 c5 c5 68 f9 c5 cd fd eb c5 dd fd d3 44 30 1c 0f } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}