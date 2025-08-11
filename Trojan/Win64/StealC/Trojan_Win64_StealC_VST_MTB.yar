
rule Trojan_Win64_StealC_VST_MTB{
	meta:
		description = "Trojan:Win64/StealC.VST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 8b 40 20 48 89 84 24 90 00 00 00 b8 fd 06 f1 b5 3d 78 51 f0 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}