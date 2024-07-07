
rule Trojan_Win32_Smokeloader_GZA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 04 33 83 ff 0f 75 90 01 01 6a 00 8d 44 24 0c 50 6a 00 6a 00 ff 15 90 01 04 46 3b f7 90 00 } //10
		$a_03_1 = {30 04 33 83 ff 0f 75 90 01 01 6a 00 8d 44 24 0c 50 68 90 01 04 ff 15 90 01 04 46 3b f7 7c 90 01 01 5d 5e 83 ff 2d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}