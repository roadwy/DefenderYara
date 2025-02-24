
rule Trojan_Win32_Smokeloader_ZSZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.ZSZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 6c 24 10 3c 8a 44 24 10 30 04 2f 83 fb 0f 75 ?? 8b 4c 24 0c 51 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}