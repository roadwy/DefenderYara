
rule Trojan_Win32_Lokibot_QWER_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.QWER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_81_0 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //1 BitConverter
		$a_81_1 = {53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e } //1 System.IO.Compression
		$a_81_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_81_3 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_81_4 = {53 79 73 74 65 6d 2e 4e 65 74 } //1 System.Net
		$a_81_5 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 DESCryptoServiceProvider
		$a_81_6 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_81_7 = {57 72 69 74 65 4c 69 6e 65 } //1 WriteLine
		$a_81_8 = {53 75 73 70 65 6e 64 4c 61 79 6f 75 74 } //1 SuspendLayout
		$a_81_9 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_10 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_11 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_12 = {53 74 61 72 74 73 57 69 74 68 } //1 StartsWith
		$a_81_13 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_14 = {56 32 6c 75 5a 47 39 33 63 30 5a 76 63 6d 31 7a 51 58 42 77 4d 53 51 3d } //1 V2luZG93c0Zvcm1zQXBwMSQ=
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1) >=15
 
}