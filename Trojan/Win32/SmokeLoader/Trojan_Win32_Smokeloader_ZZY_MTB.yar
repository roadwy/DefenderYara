
rule Trojan_Win32_Smokeloader_ZZY_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.ZZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 49 00 8d b5 ?? ?? ff ff c7 85 ?? ?? ff ff 00 00 00 00 e8 ?? ?? ?? ?? 8a 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 8b 75 0c 30 14 38 83 fe 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}