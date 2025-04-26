
rule Trojan_Win32_Smokeloader_KAE_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 ?? 03 cb 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b f3 c1 e6 ?? 03 b5 ?? ?? ?? ?? 33 f1 81 3d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}