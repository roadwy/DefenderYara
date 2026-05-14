
rule Trojan_Win64_ValleyRAT_ABMV_MTB{
	meta:
		description = "Trojan:Win64/ValleyRAT.ABMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 48 8b c1 49 f7 f0 42 0f b6 04 0a 30 04 19 48 ff c1 48 3b ce 72 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}