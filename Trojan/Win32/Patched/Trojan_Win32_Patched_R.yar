
rule Trojan_Win32_Patched_R{
	meta:
		description = "Trojan:Win32/Patched.R,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2e 64 6c 6c 00 53 66 63 47 65 74 46 69 6c 65 73 } //0a 00  搮汬匀捦敇䙴汩獥
		$a_02_1 = {83 7d 0c 00 75 90 02 20 83 3d 90 01 02 00 10 00 74 1e eb 04 89 90 01 01 4e df ff 35 90 01 02 00 10 ff 35 90 01 02 00 10 68 90 01 02 00 10 e8 90 01 02 ff ff ff d0 90 02 20 eb 07 6a 00 e8 90 01 01 00 00 00 83 3d 90 01 02 00 10 00 75 f0 90 00 } //0a 00 
		$a_03_2 = {81 c2 34 06 00 00 90 03 03 02 ff 32 5b 8b 1a 33 c3 83 e1 01 33 04 8d 90 01 02 00 10 90 00 } //01 00 
		$a_02_3 = {68 04 01 00 00 53 ff 35 90 01 02 00 10 68 90 01 02 00 10 e8 90 01 02 ff ff ff d0 8d 1d 90 01 02 00 10 eb 0b 90 00 } //01 00 
		$a_02_4 = {ff d0 8d 1d 90 01 02 00 10 6a 00 68 80 00 00 00 6a 03 6a 00 6a 03 68 00 00 00 80 53 ff 35 90 01 02 00 10 68 90 01 02 00 10 e8 90 01 02 ff ff ff d0 90 00 } //01 00 
		$a_02_5 = {81 e2 ff ff 00 00 90 02 04 03 d3 90 02 08 8a 02 35 00 90 01 01 00 00 3d cc 90 01 01 00 00 75 02 33 d0 90 02 05 ec 61 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}