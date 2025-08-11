
rule Trojan_Win64_LummaStealer_GVC_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 30 d9 30 d3 80 f2 01 44 08 c2 80 f2 01 08 da 89 c3 } //2
		$a_01_1 = {44 30 c3 44 08 c1 80 f1 01 08 d9 89 cb 30 d3 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}