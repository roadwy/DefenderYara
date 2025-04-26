
rule Trojan_Win32_Nanocore_ST_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {ad 85 c0 74 90 01 01 03 04 24 81 38 55 8b ec 83 75 ef 81 78 04 ec 0c 56 8d 75 e6 } //1
		$a_02_1 = {8b 04 0a 01 f3 [0-04] 0f ef c0 [0-04] 0f ef c9 0f 6e c0 0f 6e 0b 0f ef c1 [0-04] 51 0f 7e c1 88 c8 [0-04] 59 29 f3 [0-04] 83 c3 01 75 ?? [0-04] 89 fb [0-04] [0-04] 89 04 0a [0-04] 83 c1 01 75 c9 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Nanocore_ST_MTB_2{
	meta:
		description = "Trojan:Win32/Nanocore.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {5f 56 74 62 6c 47 61 70 31 5f 34 35 } //1 _VtblGap1_45
		$a_81_1 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_81_2 = {52 75 6e 57 6f 72 6b 65 72 41 73 79 6e 63 } //1 RunWorkerAsync
		$a_81_3 = {77 72 69 74 65 4d 65 6d 6f 72 79 } //1 writeMemory
		$a_81_4 = {52 65 67 69 73 74 65 72 48 6f 74 4b 65 79 } //1 RegisterHotKey
		$a_81_5 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_81_6 = {47 65 74 43 6c 69 70 62 6f 61 72 64 43 6f 6e 74 65 6e 74 } //1 GetClipboardContent
		$a_81_7 = {67 65 74 5f 46 75 63 68 73 69 61 } //1 get_Fuchsia
		$a_81_8 = {44 62 44 61 74 61 52 65 61 64 65 72 } //1 DbDataReader
		$a_81_9 = {42 65 67 69 6e 49 6e 76 6f 6b 65 } //1 BeginInvoke
		$a_81_10 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_81_11 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_81_12 = {43 6f 6e 66 75 73 65 72 45 78 } //1 ConfuserEx
		$a_81_13 = {24 63 31 31 31 64 37 31 35 2d 36 33 31 38 2d 34 31 35 61 2d 39 34 64 65 2d 62 65 34 35 32 38 32 33 63 38 33 39 } //1 $c111d715-6318-415a-94de-be452823c839
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}