
rule TrojanDownloader_O97M_Obfuse_PUH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PUH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {4c 69 62 20 22 75 73 65 72 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 50 6f 73 74 4d 65 73 73 61 67 65 41 22 20 28 42 79 56 61 6c } //1 Lib "user32.dll" Alias "PostMessageA" (ByVal
		$a_00_1 = {3d 20 45 6e 76 69 72 6f 6e 28 } //1 = Environ(
		$a_00_2 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 51 6d 52 58 5f 4e 44 52 20 41 73 20 4c 6f 6e 67 20 3d 20 26 48 31 30 32 } //1 Private Const QmRX_NDR As Long = &H102
		$a_00_3 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 } //1 = Join(Array(
		$a_00_4 = {43 78 73 67 77 31 42 64 20 3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 6c 63 41 61 70 5f 57 50 52 45 20 47 6e 4b 64 42 45 41 48 78 } //1 Cxsgw1Bd = Len(Join(Array("lcAap_WPRE GnKdBEAHx
		$a_00_5 = {57 69 74 68 20 47 65 74 4f 62 6a 65 63 74 28 52 64 5a 6c 68 5f 50 78 79 44 29 } //1 With GetObject(RdZlh_PxyD)
		$a_00_6 = {2e 43 72 65 61 74 65 20 56 6c 44 71 63 59 6a 6a 61 41 72 4b 4b 36 32 53 2c 20 4e 75 6c 6c 2c } //1 .Create VlDqcYjjaArKK62S, Null,
		$a_00_7 = {43 6c 6f 73 65 20 23 43 4c 6e 67 28 28 } //1 Close #CLng((
		$a_00_8 = {4f 70 65 6e 20 4d 6a 74 5a 42 5a 44 78 63 72 78 63 42 54 42 71 43 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 20 23 43 4c 6e 67 28 28 28 } //1 Open MjtZBZDxcrxcBTBqC For Binary As #CLng(((
		$a_00_9 = {50 75 74 20 23 43 4c 6e 67 28 28 } //1 Put #CLng((
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=10
 
}