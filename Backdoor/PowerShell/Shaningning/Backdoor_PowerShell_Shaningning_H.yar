
rule Backdoor_PowerShell_Shaningning_H{
	meta:
		description = "Backdoor:PowerShell/Shaningning.H,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {26 20 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 20 22 22 24 64 61 74 61 20 3d 20 5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 } //1 & "powershell -C ""$data = [System.Convert]::FromBase64String('
		$a_00_1 = {53 79 73 74 65 6d 2e 49 4f 2e 4d 65 6d 6f 72 79 53 74 72 65 61 6d 3b 24 6d 73 2e 57 72 69 74 65 28 24 64 61 74 61 2c 30 2c 24 64 61 74 61 2e 4c 65 6e 67 74 68 29 3b 24 6d 73 2e 53 65 65 6b 28 30 2c 30 29 } //1 System.IO.MemoryStream;$ms.Write($data,0,$data.Length);$ms.Seek(0,0)
		$a_00_2 = {53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 2e 47 5a 69 70 53 74 72 65 61 6d 28 24 6d 73 2c 20 5b 53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 5d 3a 3a 44 65 63 6f 6d 70 72 65 73 73 29 } //1 System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}