
rule Trojan_Win32_Smokeloader_JOZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.JOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 83 c0 46 89 44 24 0c 83 6c 24 0c ?? 8a 4c 24 0c 30 0c 2f 83 fb 0f 75 37 6a 00 6a 00 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}