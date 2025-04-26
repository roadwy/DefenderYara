
rule Trojan_Win32_LummaC_CCJQ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 17 58 50 89 c0 35 ?? ?? ?? ?? 90 90 80 07 64 80 2f 88 58 50 89 c0 35 ?? ?? ?? ?? 90 90 f6 2f 47 e2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_LummaC_CCJQ_MTB_2{
	meta:
		description = "Trojan:Win32/LummaC.CCJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 de 89 f3 21 fb 01 db 01 fe 89 f7 29 df 83 e6 ?? 83 f7 } //2
		$a_03_1 = {53 57 56 81 ec ?? ?? ?? ?? a1 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 ff e0 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}