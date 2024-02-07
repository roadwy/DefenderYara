
rule TrojanDownloader_Win32_Small_NCB{
	meta:
		description = "TrojanDownloader:Win32/Small.NCB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {44 72 69 76 65 72 73 5c 75 73 62 90 01 01 65 2e 73 79 73 90 00 } //01 00 
		$a_00_1 = {55 8b ec 53 56 57 8b 75 08 8b fe ac 0a c0 74 06 32 45 0c aa eb f5 5f 5e 5b c9 } //01 00 
		$a_00_2 = {54 49 4d 50 6c 61 74 66 6f 72 6d 2e 65 78 65 } //01 00  TIMPlatform.exe
		$a_00_3 = {69 64 3d 25 73 26 70 3d 25 73 26 6d 62 3d 25 64 26 6a 31 3d 25 73 2e 26 7a 31 3d 25 73 26 64 31 3d 25 73 26 73 72 76 3d 25 73 } //01 00  id=%s&p=%s&mb=%d&j1=%s.&z1=%s&d1=%s&srv=%s
		$a_00_4 = {6a 6c 29 40 67 6d 6c 79 6c 67 6d 6c 67 7d 29 4b 60 7d 64 68 79 } //00 00  jl)@gmlylgmlg})K`}dhy
	condition:
		any of ($a_*)
 
}