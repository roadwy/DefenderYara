
rule TrojanDownloader_Win64_LummaC_CCJR_MTB{
	meta:
		description = "TrojanDownloader:Win64/LummaC.CCJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 22 00 41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 } //1 powershell -Command "Add-MpPreference -ExclusionPath
		$a_01_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 22 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 57 00 65 00 62 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 20 00 2d 00 55 00 72 00 69 00 } //1 powershell -Command "Invoke-WebRequest -Uri
		$a_01_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 69 00 63 00 6f 00 63 00 61 00 6a 00 70 00 67 00 2f 00 66 00 61 00 72 00 6d 00 61 00 63 00 2f 00 72 00 61 00 77 00 2f 00 72 00 65 00 66 00 73 00 2f 00 68 00 65 00 61 00 64 00 73 00 2f 00 6d 00 61 00 69 00 6e 00 2f 00 } //5 https://github.com/ricocajpg/farmac/raw/refs/heads/main/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5) >=7
 
}