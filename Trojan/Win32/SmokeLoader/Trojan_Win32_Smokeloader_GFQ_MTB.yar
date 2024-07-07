
rule Trojan_Win32_Smokeloader_GFQ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 03 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 33 44 24 90 01 01 2b f8 89 44 24 90 01 01 8d 44 24 90 01 01 89 7c 24 90 01 01 e8 90 01 04 83 eb 90 01 01 0f 85 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}