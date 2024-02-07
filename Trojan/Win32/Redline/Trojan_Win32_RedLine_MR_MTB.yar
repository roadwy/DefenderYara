
rule Trojan_Win32_RedLine_MR_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 6f 20 47 6f 30 64 20 68 43 4b 4a 62 31 34 20 78 68 56 67 73 35 37 } //05 00  So Go0d hCKJb14 xhVgs57
		$a_03_1 = {83 c4 04 89 85 54 ec ff ff c7 45 fc 00 00 00 00 83 bd 54 ec ff ff 00 74 90 01 01 83 ec 18 8b cc 89 a5 0c ec ff ff 68 90 01 04 e8 90 00 } //05 00 
		$a_01_2 = {e0 00 02 01 0b 01 0e 20 00 5c 02 00 00 6a 03 00 00 00 00 00 a5 a8 } //02 00 
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 45 78 } //02 00  WaitForSingleObjectEx
		$a_01_4 = {47 65 74 43 50 49 6e 66 6f } //00 00  GetCPInfo
	condition:
		any of ($a_*)
 
}