
rule TrojanDownloader_Win64_Lazy_SX_MTB{
	meta:
		description = "TrojanDownloader:Win64/Lazy.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 04 00 00 "
		
	strings :
		$a_03_0 = {3a 2f 2f 00 c7 45 ?? 34 35 2e 39 c7 45 ?? 33 2e 32 30 c7 45 ?? 2e 36 31 00 c7 44 24 ?? 3a 35 34 36 } //30
		$a_80_1 = {73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 54 4e 20 22 4d 69 63 72 6f 73 6f 66 74 45 64 67 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 43 6f 72 65 22 20 2f 58 4d 4c 20 22 } //schtasks /Create /TN "MicrosoftEdgeUpdateTaskMachineCore" /XML "  10
		$a_80_2 = {6c 6f 64 69 6b 5f 74 61 73 6b 2e 78 6d 6c } //lodik_task.xml  5
		$a_80_3 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 20 22 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 } //powershell.exe -WindowStyle Hidden -Command "Start-Process '  5
	condition:
		((#a_03_0  & 1)*30+(#a_80_1  & 1)*10+(#a_80_2  & 1)*5+(#a_80_3  & 1)*5) >=50
 
}