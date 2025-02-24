
rule Trojan_Win32_LummaC_YKZ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.YKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af d0 01 fa 89 f7 d1 e7 83 e7 06 81 c7 ?? ?? ?? ?? 89 f0 29 f8 01 d0 30 c8 04 f1 88 44 35 e0 89 f0 83 c0 02 b9 ?? ?? ?? ?? 29 f1 83 e1 01 83 e0 0e 29 c8 89 c6 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}