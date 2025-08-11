
rule Trojan_Win64_LummaStealer_GVH_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af e8 40 f6 c5 01 0f 94 c0 0f 94 44 24 2f 83 f9 0a 0f 9c c1 0f 9c 44 24 3f 08 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}