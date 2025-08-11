
rule Trojan_Win64_LummaStealer_BW_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 da 08 c3 80 f3 01 08 d3 89 da 20 ca 80 f3 01 40 20 fb 08 d3 89 ca 30 c2 08 c1 80 f1 01 08 d1 } //3
		$a_01_1 = {30 c2 20 ca 44 20 c3 20 c1 08 d9 89 d3 30 cb } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}