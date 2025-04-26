
rule Trojan_Win32_Smokeloader_GNU_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 ce 8b 85 ?? ?? ?? ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 03 85 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c1 33 c3 2b f8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}