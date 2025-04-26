
rule TrojanDownloader_Win32_Bitsaload_MK_MTB{
	meta:
		description = "TrojanDownloader:Win32/Bitsaload.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 63 6f 6d 6d 61 6e 64 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 [0-0a] 2e 65 78 65 3b 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 [0-0a] 2e 65 78 65 } //10
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 63 6f 6d 6d 61 6e 64 20 49 6d 70 6f 72 74 2d 4d 6f 64 75 6c 65 20 42 69 74 73 54 72 61 6e 73 66 65 72 3b 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 } //10 powershell -command Import-Module BitsTransfer; Start-BitsTransfer
		$a_03_2 = {68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f [0-12] 2f 50 68 6f 65 6e 69 78 4d 69 6e 65 72 2e 65 78 65 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 [0-0a] 2e 65 78 65 2c [0-0a] 2e 65 78 65 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10) >=30
 
}