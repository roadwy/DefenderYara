
rule Trojan_Win64_LummaStealer_BV_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 c8 08 d9 20 da 08 c2 89 c8 30 d0 } //3
		$a_01_1 = {30 d0 20 d8 40 20 f1 20 d3 08 cb 89 c1 30 d9 b9 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}