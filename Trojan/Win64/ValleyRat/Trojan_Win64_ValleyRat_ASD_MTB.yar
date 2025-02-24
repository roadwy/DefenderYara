
rule Trojan_Win64_ValleyRat_ASD_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c8 b8 cd cc cc cc 41 f7 e2 80 c1 36 49 8d 43 01 41 30 4c 38 ff 45 33 db c1 ea 03 41 ff c2 8d 0c 92 03 c9 44 3b c9 4c 0f 45 d8 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}