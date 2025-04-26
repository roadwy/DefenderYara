
rule TrojanDownloader_Win32_Agent_FX{
	meta:
		description = "TrojanDownloader:Win32/Agent.FX,SIGNATURE_TYPE_PEHSTR,30 01 2f 01 07 00 00 "
		
	strings :
		$a_01_0 = {5c 6d 66 2a 2e 64 6c 6c } //100 \mf*.dll
		$a_01_1 = {5c 77 69 6e 61 63 63 65 73 74 6f 72 2e 64 61 74 } //100 \winaccestor.dat
		$a_01_2 = {43 4c 53 49 44 5c 7b 41 38 39 38 31 44 42 39 2d 42 32 42 33 2d 34 37 44 37 2d 41 38 39 30 2d 39 43 39 44 39 46 34 43 35 35 35 32 7d } //100 CLSID\{A8981DB9-B2B3-47D7-A890-9C9D9F4C5552}
		$a_01_3 = {72 65 67 73 76 72 33 32 20 2f 73 } //1 regsvr32 /s
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 50 72 69 76 61 63 79 20 50 72 6f 6a 65 63 74 } //1 Software\Privacy Project
		$a_01_6 = {53 6d 61 72 74 20 43 6f 6e 74 65 6e 74 20 50 72 6f 74 65 63 74 6f 72 } //1 Smart Content Protector
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=303
 
}