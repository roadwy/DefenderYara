
rule Backdoor_Win64_ValleyRAT_GMH_MTB{
	meta:
		description = "Backdoor:Win64/ValleyRAT.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c8 b8 cd cc cc cc 41 f7 e1 80 c1 ?? 49 8d 43 ?? 43 30 4c 10 ?? 45 33 db c1 ea 03 8d 0c 92 03 c9 44 3b c9 4c 0f 45 d8 41 ff c1 44 3b cb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}