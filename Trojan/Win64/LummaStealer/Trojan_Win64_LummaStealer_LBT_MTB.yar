
rule Trojan_Win64_LummaStealer_LBT_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.LBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 f6 d1 80 e1 46 24 b9 08 c8 89 c1 80 f1 55 34 aa 89 ca 80 e2 fe 24 ?? 80 e1 ?? 08 c1 89 d0 20 c8 30 d1 08 c1 89 c8 f6 d0 24 67 80 e1 98 08 c1 80 f1 98 b8 ad 08 0c 30 41 0f 44 c6 3d ac 08 0c 30 0f 8f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}