
rule Trojan_BAT_AgentTesla_EBF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {0b bf f2 5b 5f f0 77 5d f0 85 0b 7e 8d 97 63 f0 6b ae eb eb cf 57 40 d7 ff e2 38 3f c1 1f 74 c0 fd bf 09 df 63 5d ff 86 17 7c 9d 0b fe a5 97 73 } //1
		$a_01_1 = {1d 9f 75 0e 3e e3 77 ea 33 8e 3a 3f f1 99 a7 f1 b9 9e 7c e6 db 3b 3e ef 80 e1 73 9f 3f f9 cc 0d 77 7c ea 04 be d6 83 d1 1a c7 77 7c ee 37 f1 ed } //1
		$a_01_2 = {3a 3e 1b 8f f2 74 cb cf 9e 67 fd 6d fc b9 c7 72 cc 9e 47 d7 9e 9b 39 06 de 4d 72 74 8f ec 98 fd bb 7e d4 0f db de 9d 5f f9 f9 ec b8 69 bc 44 57 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}