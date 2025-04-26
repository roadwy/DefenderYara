
rule Trojan_Win64_ShellCoExec_B_MTB{
	meta:
		description = "Trojan:Win64/ShellCoExec.B!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b7 cb 48 63 ed 66 99 48 13 fd 41 0f b6 eb 4c 8b 54 43 e2 d3 c2 0f ba e0 b9 48 8b 44 13 08 66 c1 fa e7 8a 4c 13 10 2b ea 48 8d 5c 53 0a 66 c1 ed 2a c0 fa 87 49 0f a5 c2 4c 89 14 13 48 03 d7 ff e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}