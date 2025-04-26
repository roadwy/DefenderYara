
rule Trojan_Win32_SmokeLoader_XV_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.XV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 89 45 f0 8b 45 e4 8b 4d e8 d3 e8 89 45 f8 8b 45 cc 01 45 f8 8b 7d e4 c1 e7 04 03 7d d8 33 7d f0 81 3d e4 ba 8e 00 ?? ?? ?? ?? 75 09 56 56 56 ff 15 ?? ?? ?? ?? 33 7d f8 89 35 ?? ?? ?? ?? 89 7d c8 8b 45 c8 29 45 f4 8b 45 dc 29 45 fc ff 4d e0 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}