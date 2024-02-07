
rule Trojan_Win32_Gozi_MA_MTB{
	meta:
		description = "Trojan:Win32/Gozi.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 ea 10 88 14 08 8b d3 ff 05 90 01 04 8b 4e 64 8b 86 88 00 00 00 c1 ea 08 88 14 01 ff 46 64 8b 0d 90 01 04 8b 81 08 01 00 00 35 90 01 04 01 05 90 01 04 8b 89 88 00 00 00 8b 46 64 88 1c 01 ff 46 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 75 c8 01 f1 81 e1 90 01 04 8b 75 ec 8b 5d cc 8a 1c 1e 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 cc 88 1c 31 8b 4d f0 39 cf 8b 4d c4 89 4d dc 89 7d d8 89 55 d4 0f 85 90 00 } //01 00 
		$a_01_1 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 41 } //01 00  FindNextFileA
		$a_01_2 = {49 73 57 69 6e 45 76 65 6e 74 48 6f 6f 6b 49 6e 73 74 61 6c 6c 65 64 } //00 00  IsWinEventHookInstalled
	condition:
		any of ($a_*)
 
}