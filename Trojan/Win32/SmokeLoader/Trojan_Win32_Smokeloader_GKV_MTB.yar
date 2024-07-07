
rule Trojan_Win32_Smokeloader_GKV_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 55 f8 0f b6 02 33 c1 8b 0d 90 01 04 03 4d f8 88 01 eb b7 90 0a 33 00 0f b6 0d 90 01 04 8b 15 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}