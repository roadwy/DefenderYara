
rule Trojan_Win32_LummaC_CCJP_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 8b 4d ec 0f b6 0c 0f 05 ?? ?? ?? ?? 31 c8 89 45 e8 8b 45 e8 04 6e 8b 4d ec 88 04 0f ff 45 ec 8b 45 ec 83 f8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}