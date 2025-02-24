
rule Trojan_Win32_StealC_NNP_MTB{
	meta:
		description = "Trojan:Win32/StealC.NNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 de 8a 18 a1 ?? ?? ?? ?? 01 c8 89 e9 57 ff d0 30 18 89 f3 be d5 4c ca d0 47 a1 1c c1 43 00 01 f0 89 e9 ff d0 39 c7 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}