
rule Trojan_Win32_Smokeloader_GHL_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 e2 ?? 03 54 24 ?? 8d 0c 07 c1 e8 ?? 89 54 24 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 c1 31 44 24 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}