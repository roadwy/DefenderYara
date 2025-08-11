
rule Trojan_Win64_LummaStealer_GVD_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 30 c0 44 89 c2 80 f2 01 20 c2 } //2
		$a_01_1 = {0f 9c c0 41 30 c0 44 89 c2 f6 d2 20 c2 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}