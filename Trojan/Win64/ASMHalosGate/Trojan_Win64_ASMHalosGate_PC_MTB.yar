
rule Trojan_Win64_ASMHalosGate_PC_MTB{
	meta:
		description = "Trojan:Win64/ASMHalosGate.PC!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 f1 8b c2 8b c0 48 8d 0d 2e 2c 00 00 8b 54 24 54 33 14 81 8b c2 8b 4c 24 30 48 8b 54 24 40 88 04 0a } //1
		$a_01_1 = {62 63 6f 6f 6b 65 73 48 61 6c 6f 73 47 61 74 65 2e 70 64 62 } //1 bcookesHalosGate.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}