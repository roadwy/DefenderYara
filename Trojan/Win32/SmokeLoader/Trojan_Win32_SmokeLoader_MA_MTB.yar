
rule Trojan_Win32_SmokeLoader_MA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 7d f4 8b c7 c1 e0 04 03 45 e0 89 45 f8 8b 45 f4 03 45 f0 89 45 0c ff 75 0c 83 0d 90 01 04 ff 8b d7 8d 45 f8 c1 ea 05 03 55 e8 50 c7 05 90 00 } //05 00 
		$a_03_1 = {6a 73 58 6a 6d 66 a3 90 01 04 58 6a 67 66 a3 90 01 04 58 6a 69 66 a3 90 01 04 58 6a 6c 66 a3 90 01 04 58 6a 32 66 a3 90 01 04 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}