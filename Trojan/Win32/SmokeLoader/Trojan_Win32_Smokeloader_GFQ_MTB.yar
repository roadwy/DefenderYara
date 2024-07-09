
rule Trojan_Win32_Smokeloader_GFQ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 03 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 33 44 24 ?? 2b f8 89 44 24 ?? 8d 44 24 ?? 89 7c 24 ?? e8 ?? ?? ?? ?? 83 eb ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}