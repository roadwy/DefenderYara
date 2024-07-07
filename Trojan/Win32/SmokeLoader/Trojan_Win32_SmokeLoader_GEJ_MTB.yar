
rule Trojan_Win32_SmokeLoader_GEJ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 07 c1 e8 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 51 8d 45 90 01 01 50 c7 05 90 01 04 fc 03 cf ff e8 90 01 04 8b 45 90 01 01 33 45 90 01 01 83 25 90 01 05 2b f0 89 45 90 01 01 8b c6 c1 e0 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 03 fe 81 3d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}