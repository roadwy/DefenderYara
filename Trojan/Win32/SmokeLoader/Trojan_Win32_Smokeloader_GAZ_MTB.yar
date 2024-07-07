
rule Trojan_Win32_Smokeloader_GAZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 69 c9 90 01 04 81 c1 90 01 04 89 0d 90 01 04 8a 15 90 01 04 30 14 30 83 7c 24 90 01 01 0f 90 01 02 6a 00 6a 00 6a 00 ff d3 90 00 } //10
		$a_03_1 = {8b 44 24 10 69 c9 90 01 04 81 c1 90 01 04 89 0d 90 01 04 8a 15 90 01 04 30 14 30 83 90 01 01 24 90 01 04 0f 90 01 02 6a 00 6a 00 6a 00 ff 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}