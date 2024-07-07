
rule Trojan_Win32_Smokeloader_GAC_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 a1 90 01 04 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 90 01 04 8a 0d 90 01 04 30 0c 33 83 ff 0f 75 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}