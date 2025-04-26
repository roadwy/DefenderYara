
rule Trojan_Win32_Smokeloader_GHQ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 06 c1 e8 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 c1 31 44 24 ?? 81 3d ?? ?? ?? ?? ba 05 00 00 89 44 24 ?? 89 1d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}