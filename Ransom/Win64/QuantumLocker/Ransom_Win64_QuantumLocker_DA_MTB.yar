
rule Ransom_Win64_QuantumLocker_DA_MTB{
	meta:
		description = "Ransom:Win64/QuantumLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 1f 80 00 00 00 00 0f b6 c3 41 2a c4 32 03 40 32 c7 88 03 49 03 df 48 3b dd 72 90 01 01 48 ff c6 49 ff c5 49 ff ce 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}