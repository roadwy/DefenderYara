
rule Trojan_Win64_LummaStealer_DZ_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 0f b6 04 27 4c 89 ef 44 8b 6d 98 0f b6 0c 1e 01 c1 0f b6 c1 48 8b 4d b0 0f b6 04 01 48 63 4d f0 48 8b 55 88 30 04 0a 44 8b 65 f0 41 83 c4 01 b8 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}