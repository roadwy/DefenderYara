
rule Trojan_Win32_IStartSurf_PVS_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 5d 9c 83 c3 01 f7 f3 89 45 b4 68 90 01 04 5a 0b d0 c1 e2 0a 89 55 cc 90 00 } //02 00 
		$a_00_1 = {8b 45 cc 48 89 45 cc 8b 45 b4 83 c8 0c 39 45 cc 0f 87 } //02 00 
		$a_00_2 = {8b 40 36 8b 4d d8 8b 04 01 89 45 e0 8b 45 e0 33 d2 b9 00 00 01 00 f7 f1 8b 45 e0 2b c2 89 45 e0 } //00 00 
	condition:
		any of ($a_*)
 
}