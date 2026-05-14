
rule Trojan_Win64_Vidar_SAH_MTB{
	meta:
		description = "Trojan:Win64/Vidar.SAH!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 89 d0 48 f7 ea 4c 01 c2 48 c1 fa 06 4d 89 c1 49 c1 f8 3f 4c 29 c2 48 6b d2 61 4d 89 c8 49 29 d1 41 31 f1 48 89 da 48 c1 e3 05 48 29 d3 44 31 cb 88 1c 11 48 89 d3 e9 59 ff ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}