
rule TrojanDownloader_Win32_Clikug_A{
	meta:
		description = "TrojanDownloader:Win32/Clikug.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {7a 00 67 00 69 00 67 00 61 00 63 00 6c 00 69 00 63 00 6b 00 73 00 00 00 } //2
		$a_01_1 = {2e 3f 41 56 43 47 69 67 61 43 6c 69 63 6b 73 49 6e 66 6f 40 40 } //2 .?AVCGigaClicksInfo@@
		$a_01_2 = {2e 3f 41 56 43 54 69 6e 79 49 6e 73 74 61 6c 6c 65 72 41 70 70 40 40 } //1 .?AVCTinyInstallerApp@@
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
rule TrojanDownloader_Win32_Clikug_A_2{
	meta:
		description = "TrojanDownloader:Win32/Clikug.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 43 4f 70 74 69 6d 69 7a 65 72 50 72 6f 49 6e 66 6f 40 40 } //1 .?AVCOptimizerProInfo@@
		$a_01_1 = {2e 3f 41 56 43 4c 6f 6c 69 70 6f 70 65 46 52 49 6e 66 6f 40 40 } //1 .?AVCLolipopeFRInfo@@
		$a_01_2 = {2e 3f 41 56 43 50 43 46 69 78 53 70 65 65 64 49 6e 66 6f 40 40 } //1 .?AVCPCFixSpeedInfo@@
		$a_01_3 = {2e 3f 41 56 43 47 69 67 61 43 6c 69 63 6b 73 49 6e 66 6f 40 40 } //2 .?AVCGigaClicksInfo@@
		$a_01_4 = {2e 3f 41 56 43 54 69 6e 79 49 6e 73 74 61 6c 6c 65 72 41 70 70 40 40 } //1 .?AVCTinyInstallerApp@@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=5
 
}