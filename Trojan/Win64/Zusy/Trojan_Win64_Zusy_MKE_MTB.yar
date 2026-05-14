
rule Trojan_Win64_Zusy_MKE_MTB{
	meta:
		description = "Trojan:Win64/Zusy.MKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 ca 81 ea 1f 9c 3a 86 83 ea 01 81 c2 1f 9c 3a 86 0f af ca 83 e1 01 83 f9 00 0f 94 c1 83 f8 0a 0f 9c c2 88 c8 20 d0 30 d1 08 c8 a8 01 } //20
		$a_01_1 = {89 ca 81 c2 2e 23 cd 35 83 ea 01 81 ea 2e 23 cd 35 0f af ca 83 e1 01 83 f9 00 41 0f 94 c3 83 f8 0a 41 0f 9c c2 44 88 d9 80 f1 ff 45 88 d0 41 80 f0 ff b2 01 80 f2 00 88 c8 } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}