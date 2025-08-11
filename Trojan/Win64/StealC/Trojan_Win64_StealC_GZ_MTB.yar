
rule Trojan_Win64_StealC_GZ_MTB{
	meta:
		description = "Trojan:Win64/StealC.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f 94 c0 0f 94 44 24 7f 83 fd 0a 0f 9c 84 24 ?? ?? ?? ?? 4d 89 c6 49 89 d4 49 89 cd 0f 9c c1 08 c1 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}