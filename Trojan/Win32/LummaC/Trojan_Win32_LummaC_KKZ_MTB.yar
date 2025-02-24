
rule Trojan_Win32_LummaC_KKZ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.KKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d0 83 e0 16 89 f3 81 f3 ?? ?? ?? ?? 29 c3 fe c3 32 19 80 c3 37 88 19 41 4e 83 c2 fe 83 fe f0 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}