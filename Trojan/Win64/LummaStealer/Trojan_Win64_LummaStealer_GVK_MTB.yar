
rule Trojan_Win64_LummaStealer_GVK_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af c8 f6 c1 01 0f 94 c0 0f 94 45 1f 41 83 fa 0a 0f 9c c2 0f 9c 45 2f 08 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}