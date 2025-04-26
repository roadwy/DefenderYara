
rule Trojan_Win64_LummaStealer_AMW_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.AMW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 ff c1 49 63 c9 8a 04 19 41 88 04 1a 44 88 1c 19 41 0f b6 0c 1a 49 03 cb 0f b6 c1 8a 0c 18 41 30 0e 49 ff c6 48 83 ef 01 75 a9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}