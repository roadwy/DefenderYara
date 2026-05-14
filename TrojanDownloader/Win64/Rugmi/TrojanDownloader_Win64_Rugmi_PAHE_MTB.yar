
rule TrojanDownloader_Win64_Rugmi_PAHE_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.PAHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 20 30 75 00 00 41 b9 30 75 00 00 41 b8 30 75 00 00 ba 30 75 00 00 48 89 c1 ff } //2
		$a_01_1 = {6b 61 73 6b 64 6b 77 71 6b 77 71 65 2e 73 70 61 63 65 2f 77 69 6e 36 34 2e 65 78 65 } //1 kaskdkwqkwqe.space/win64.exe
		$a_01_2 = {5c 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //1 \installer.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}