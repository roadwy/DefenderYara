
rule Trojan_Win32_SmokeLoader_PADH_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PADH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 ea 89 45 ec 8b 45 fc c7 05 ac b3 af 02 ee 3d ea f4 03 55 d4 89 45 e8 89 75 f0 8b 45 ec 01 45 f0 8b 45 f0 31 45 e8 8b 45 e8 33 d0 89 45 fc 89 55 f0 8b 45 f0 83 45 f8 64 29 45 f8 83 6d f8 64 8b 45 f8 c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 45 f8 8d 0c 03 89 4d ec 8b 4d f4 d3 e8 03 45 d0 89 45 f0 8b 45 ec 31 45 fc 81 3d b4 b3 af 02 03 0b 00 00 75 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}