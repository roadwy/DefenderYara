
rule Trojan_Win64_Latrodectus_GNE_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 30 14 0f c5 fd fd db c5 d5 fd f5 48 ff c1 c5 c5 71 d7 ?? c5 fd 6f c8 c5 fd 6f da c5 fd 6f ec 48 89 c8 c5 ed 67 d2 c5 e5 67 db 48 81 f9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}