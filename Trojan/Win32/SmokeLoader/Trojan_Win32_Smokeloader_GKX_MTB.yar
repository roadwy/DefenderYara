
rule Trojan_Win32_Smokeloader_GKX_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 d3 e8 89 35 90 01 04 03 45 dc 89 45 f8 33 c7 31 45 fc 8b 45 f0 89 45 e4 8b 45 fc 29 45 e4 8b 45 e4 89 45 f0 8b 45 c4 29 45 f4 ff 4d d8 0f 85 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}