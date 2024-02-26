
rule Trojan_Win32_Fauppod_MA_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 66 67 68 47 76 79 67 75 62 68 } //02 00  RfghGvygubh
		$a_01_1 = {4c 6a 6e 68 44 64 63 74 66 76 67 } //02 00  LjnhDdctfvg
		$a_01_2 = {59 74 62 46 66 74 76 79 67 } //01 00  YtbFftvyg
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fauppod_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Fauppod.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {e8 de ff ff ff 40 90 0a 2a 00 e8 90 01 02 ff ff 8d 05 90 01 04 89 18 89 f0 01 05 90 01 04 89 ea 01 15 90 00 } //01 00 
		$a_01_1 = {89 45 00 55 89 e5 83 e4 f8 83 ec 70 31 c0 89 44 24 60 8b 44 24 60 } //01 00 
		$a_01_2 = {8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75 e2 } //00 00 
	condition:
		any of ($a_*)
 
}