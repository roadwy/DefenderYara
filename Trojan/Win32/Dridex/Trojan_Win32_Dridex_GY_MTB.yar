
rule Trojan_Win32_Dridex_GY_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 7d 00 8a d8 2a da 80 eb 90 01 01 88 1d 90 01 04 0f b7 da 83 c1 90 01 01 89 0d 90 01 04 39 1d 90 01 04 90 18 81 c7 90 01 04 89 7d 00 89 3d 90 01 04 8d 3c 00 2b 3d 90 01 04 83 c5 04 2b fe 03 d7 83 6c 24 90 01 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}