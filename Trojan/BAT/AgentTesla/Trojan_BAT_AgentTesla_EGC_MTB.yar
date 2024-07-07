
rule Trojan_BAT_AgentTesla_EGC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 3e f0 b3 09 4c 34 48 06 2d 00 3d 2f 2e 7c 69 0e 64 04 42 20 60 3a c4 fc f5 42 e4 cd 6c cb 02 66 22 68 49 e1 53 65 2f ac bd dd a8 df 33 f2 1d } //1
		$a_01_1 = {48 1d dd ae df 31 22 b0 d0 4d db df f8 a8 0d 39 34 37 d0 4e 10 39 48 bd ed a8 2f c3 22 40 d0 4d d8 d9 55 2b d5 a4 c4 d7 e0 be 30 29 48 bd a5 a9 } //1
		$a_01_2 = {dd a8 df 33 22 b0 d0 4d d8 d9 45 2b c5 a4 c4 d7 e0 be 30 29 48 bd dd a8 df 33 22 b0 d0 4d d8 d9 45 2b c5 a4 c4 d7 e0 be 30 29 48 bd dd a8 df 33 } //1
		$a_01_3 = {30 29 48 bd dd a8 df 33 22 b0 d0 4d d8 d9 45 2b c5 a4 c4 d7 e0 be 30 29 48 bd dd a8 df 33 22 b0 d0 4d d8 d9 45 2b c5 a4 c4 d7 e0 be 30 29 48 bd } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}