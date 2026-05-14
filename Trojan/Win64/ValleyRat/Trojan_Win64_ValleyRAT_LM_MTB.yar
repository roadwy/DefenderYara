
rule Trojan_Win64_ValleyRAT_LM_MTB{
	meta:
		description = "Trojan:Win64/ValleyRAT.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 43 10 48 ff c7 80 74 07 ff 22 48 ff c9 } //20
		$a_01_1 = {c7 85 a0 04 00 00 57 72 69 74 c7 85 a4 04 00 00 65 50 72 6f c7 85 a8 04 00 00 63 65 73 73 c7 85 ac 04 00 00 4d 65 6d 6f 66 c7 85 b0 04 00 00 72 79 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}