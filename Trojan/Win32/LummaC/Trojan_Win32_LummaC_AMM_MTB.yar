
rule Trojan_Win32_LummaC_AMM_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 eb 83 e2 09 89 c5 81 e5 ?? ?? ?? ?? 09 d5 31 dd 81 f5 ?? ?? ?? ?? 09 ef 89 f3 f7 d3 89 fa 21 da 89 fd 21 f5 29 fe 8d 14 56 31 fb 01 fb 29 eb 21 d3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}