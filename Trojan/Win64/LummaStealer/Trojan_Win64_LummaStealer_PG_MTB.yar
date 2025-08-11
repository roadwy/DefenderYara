
rule Trojan_Win64_LummaStealer_PG_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 80 f6 00 45 08 da 40 80 ce 00 41 80 f2 ff 41 20 f2 41 88 fb 41 80 f3 ff 40 88 de 44 20 de 80 f3 ff 40 20 df 40 08 fe 45 88 d3 41 20 f3 41 30 f2 45 08 d3 41 f6 c3 01 b8 37 89 da 81 b9 29 a3 60 75 0f 45 c8 89 4c 24 64 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}