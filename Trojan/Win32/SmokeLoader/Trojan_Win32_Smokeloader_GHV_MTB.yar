
rule Trojan_Win32_Smokeloader_GHV_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 ?? 03 cb 8b 44 24 ?? 31 44 24 ?? 8b 54 24 ?? 52 51 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 ?? 47 86 c8 61 83 ed } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}