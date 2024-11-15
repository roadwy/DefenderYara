
rule Trojan_Win32_Smokeloader_ZAZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.ZAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 8d a4 24 00 00 00 00 8d 74 24 10 c7 44 24 0c 05 00 00 00 c7 44 24 10 00 00 00 00 e8 ?? ?? ?? ?? 8b 44 24 10 83 c0 46 89 44 24 0c 83 6c 24 0c ?? 8a 4c 24 0c 30 0c 2f 83 fb 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}