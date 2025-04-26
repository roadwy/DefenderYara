
rule Trojan_Win64_ShellCoExec_A_MTB{
	meta:
		description = "Trojan:Win64/ShellCoExec.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 63 c1 48 b8 5f 43 79 0d e5 35 94 d7 41 ff c1 49 f7 e0 48 c1 ea 04 48 6b c2 13 4c 2b c0 41 8b c3 44 03 db 99 4d 03 c7 f7 fb 48 63 c8 48 b8 d0 93 1c 40 01 00 00 00 48 03 c1 42 8a 4c 04 20 32 0c 30 41 88 0a 49 ff c2 41 81 f9 00 12 01 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}