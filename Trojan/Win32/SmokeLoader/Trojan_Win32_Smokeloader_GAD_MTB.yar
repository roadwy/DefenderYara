
rule Trojan_Win32_Smokeloader_GAD_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c6 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 2b 7c 24 90 01 01 81 c5 47 86 c8 61 ff 4c 24 90 01 01 0f 85 90 01 04 81 3d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}