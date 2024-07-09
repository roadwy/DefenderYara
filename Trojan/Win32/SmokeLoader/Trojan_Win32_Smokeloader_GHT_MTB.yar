
rule Trojan_Win32_Smokeloader_GHT_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 c5 03 fe 31 7c 24 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8d 44 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}