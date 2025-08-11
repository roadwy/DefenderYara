
rule Trojan_Win64_LummaStealer_DQ_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 9f c2 30 d1 89 d3 20 c3 30 c2 08 da 89 cb 30 d3 84 d2 b8 ?? ?? ?? ?? ba ?? ?? ?? ?? 0f 45 c2 84 c9 0f 45 c2 84 db b9 ?? ?? ?? ?? e9 } //10
		$a_03_1 = {0f 9f c1 89 c2 30 ca 20 c1 08 d1 89 cb 30 d3 84 c9 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 0f 45 c1 84 d2 0f 44 c1 84 db b9 ?? ?? ?? ?? e9 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}