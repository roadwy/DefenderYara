
rule Trojan_Win64_LummaStealer_GVM_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 01 30 d0 88 44 24 27 44 89 ce e9 } //2
		$a_01_1 = {44 30 c2 48 8b 84 24 d0 08 00 00 88 10 48 8b 84 24 a0 03 00 00 48 83 c0 01 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}