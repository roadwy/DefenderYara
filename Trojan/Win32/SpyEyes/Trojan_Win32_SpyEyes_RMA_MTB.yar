
rule Trojan_Win32_SpyEyes_RMA_MTB{
	meta:
		description = "Trojan:Win32/SpyEyes.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 eb ?? 8b 45 ?? 05 f8 00 00 00 89 45 ?? 8b 4d ?? 51 e8 ?? ?? ?? ?? 83 c4 04 c7 45 ?? 00 00 00 00 eb ?? 8b 55 ?? 83 c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}