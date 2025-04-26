
rule TrojanDownloader_O97M_Obfuse_PW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {23 49 66 20 57 69 6e 36 34 20 54 68 65 6e } //1 #If Win64 Then
		$a_01_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 76 70 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 22 20 28 42 79 56 61 6c 20 78 31 20 41 73 20 4c 6f 6e 67 50 74 72 2c } //1 Private Declare PtrSafe Function vp Lib "kernel32" Alias "VirtualProtect" (ByVal x1 As LongPtr,
		$a_01_2 = {73 20 3d 20 22 36 46 22 } //1 s = "6F"
		$a_01_3 = {73 20 3d 20 73 20 26 20 22 } //1 s = s & "
		$a_01_4 = {56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 28 73 2c 20 6b 2c 20 32 29 29 } //1 Val("&H" & Mid(s, k, 2))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_PW_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 73 78 2d 66 61 63 65 6d 61 73 6b 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 74 68 65 6d 65 73 2f 62 75 73 69 66 79 2f 5f 45 62 2d 36 58 5a 51 50 6b 65 57 46 45 32 46 30 2e 70 68 70 3f 78 3d 4d 44 41 77 4d 53 43 58 66 4d 30 32 43 6d 67 51 6e 6b 2d 44 4d 6d 77 5a 36 69 71 50 43 46 48 74 7a 6f 65 61 52 4c 66 5a 72 7a 4c 70 69 50 7a 76 49 4f 53 69 68 44 68 7a 70 39 49 53 57 34 62 70 47 39 32 6d 6d 4e 75 69 48 51 4e 4d 45 6b 4c 56 72 55 6d 45 7a 36 6b 6f 59 7a 58 37 30 78 56 4d 47 66 36 6a 56 43 71 51 65 52 56 65 37 74 38 35 55 4a 36 51 5f 72 37 6f 47 77 79 5a 47 7a 48 6e 4b 5a 4b 31 4f 2d 6a 7a 76 43 44 59 61 5a 53 67 33 56 75 59 44 52 76 44 } //3 https://sx-facemask.com/wp-content/themes/busify/_Eb-6XZQPkeWFE2F0.php?x=MDAwMSCXfM02CmgQnk-DMmwZ6iqPCFHtzoeaRLfZrzLpiPzvIOSihDhzp9ISW4bpG92mmNuiHQNMEkLVrUmEz6koYzX70xVMGf6jVCqQeRVe7t85UJ6Q_r7oGwyZGzHnKZK1O-jzvCDYaZSg3VuYDRvD
		$a_00_1 = {3d 20 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c } //1 = "wscript.shell
		$a_00_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 65 70 20 62 79 70 61 73 73 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 65 6e 63 20 } //1 powershell -nop -ep bypass -windowstyle hidden -enc 
		$a_00_3 = {2e 52 75 6e 24 20 70 61 79 6c 6f 61 64 } //1 .Run$ payload
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}