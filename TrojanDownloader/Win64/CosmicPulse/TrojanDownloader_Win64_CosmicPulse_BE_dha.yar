
rule TrojanDownloader_Win64_CosmicPulse_BE_dha{
	meta:
		description = "TrojanDownloader:Win64/CosmicPulse.BE!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 00 4b 00 48 00 54 00 4d 00 4c 00 2c 00 20 00 6c 00 69 00 6b 00 65 00 20 00 47 00 65 00 63 00 6b 00 6f 00 29 00 20 00 43 00 68 00 72 00 6f 00 6d 00 65 00 2f 00 31 00 33 00 31 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 53 00 61 00 66 00 61 00 72 00 69 00 2f 00 35 00 33 00 37 00 2e 00 33 00 36 00 20 00 45 00 64 00 67 00 2f 00 31 00 33 00 33 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 48 00 45 00 41 00 44 00 2f 00 } //1 (KHTML, like Gecko) Chrome/131.0.0.0.1 Safari/537.36 Edg/133.0.0.0.1 HEAD/
		$a_01_1 = {6f 6c 65 64 6c 67 2e 64 6c 6c 2e 4f 6c 65 55 49 42 75 73 79 57 } //1 oledlg.dll.OleUIBusyW
		$a_40_2 = {00 49 00 44 00 01 } //1 䤀䐀Ā
		$a_63_3 = {6d } //2560 m
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_40_2  & 1)*1+(#a_63_3  & 1)*2560) >=4
 
}