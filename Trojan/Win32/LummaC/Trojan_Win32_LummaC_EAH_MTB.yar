
rule Trojan_Win32_LummaC_EAH_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d ec 80 c1 22 88 8c 1e 86 87 6c 1e 40 89 45 e8 8b 45 e0 43 48 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}