
rule TrojanDownloader_Win64_AsyncRAT_C_MTB{
	meta:
		description = "TrojanDownloader:Win64/AsyncRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 63 75 72 6c 20 2d 6f 20 25 74 65 6d 70 25 5c } //02 00  cmd.exe /c curl -o %temp%\
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 73 74 61 72 74 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 68 69 64 64 65 6e 20 25 74 65 6d 70 25 5c } //00 00  powershell start -WindowStyle hidden %temp%\
	condition:
		any of ($a_*)
 
}