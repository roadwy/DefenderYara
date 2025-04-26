
rule TrojanDownloader_Win32_Nonaco_I{
	meta:
		description = "TrojanDownloader:Win32/Nonaco.I,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1e 00 0c 00 00 "
		
	strings :
		$a_00_0 = {55 73 65 72 49 64 } //1 UserId
		$a_00_1 = {6c 69 76 65 2e } //1 live.
		$a_00_2 = {72 64 73 2e 79 61 68 6f 6f 2e } //1 rds.yahoo.
		$a_00_3 = {79 61 68 6f 6f 2e } //1 yahoo.
		$a_00_4 = {67 6f 6f 67 6c 65 2e } //1 google.
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //1 Software\Microsoft\Internet Explorer
		$a_00_6 = {62 68 6f 3d 31 26 76 3d 32 39 26 73 65 3d 25 73 26 75 73 65 72 3d 25 73 26 6c 61 6e 67 3d 25 73 } //2 bho=1&v=29&se=%s&user=%s&lang=%s
		$a_00_7 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 62 69 6e 25 73 65 74 2d 73 74 72 65 61 6d } //1 Content-Type: bin%set-stream
		$a_00_8 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 25 73 } //1 User-Agent: %s
		$a_00_9 = {49 6e 76 6f 6b 65 20 64 69 73 70 69 64 20 3d 20 25 64 } //1 Invoke dispid = %d
		$a_00_10 = {43 4c 53 49 44 5c 65 34 30 35 2e 65 34 30 35 6d 67 72 } //10 CLSID\e405.e405mgr
		$a_02_11 = {46 47 83 fe 03 75 ?? 8a 45 ?? 8a cb c0 e8 02 88 ?? 0c 8a 45 ?? 24 03 c0 e0 04 c0 e9 04 02 c1 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*2+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*10+(#a_02_11  & 1)*10) >=30
 
}