
rule Trojan_Win64_Latrodectus_MJV_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.MJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 f7 f2 48 83 c2 03 45 8a 5c 15 ?? 66 0f 70 fe 00 66 0f 70 fd 00 66 0f f1 da 66 0f f1 ec 66 0f 70 f7 00 66 0f 70 f3 00 66 0f 70 fe 00 66 0f 70 fc 00 c5 fc 28 c1 c5 fc 28 d3 c4 e2 7d 00 c4 c4 e2 6d 00 d5 c5 e5 73 db ?? c4 e2 7d 40 c3 c4 e2 6d 40 d4 44 30 1c 0f 66 0f 70 fa 00 66 0f e5 d4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}