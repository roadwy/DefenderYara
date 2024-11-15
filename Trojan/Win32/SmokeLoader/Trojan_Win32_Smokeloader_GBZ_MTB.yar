
rule Trojan_Win32_Smokeloader_GBZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 04 37 6a 00 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 6a 00 ff 15 ?? ?? ?? ?? 46 3b f3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}