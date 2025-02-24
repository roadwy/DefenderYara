
rule Ransom_MSIL_Filecoder_AKK_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.AKK!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 61 6e 61 67 65 72 } //2 DisableTaskManager
		$a_01_1 = {44 69 73 61 62 6c 65 46 69 72 65 66 6f 78 44 6f 77 6e 6c 6f 61 64 73 } //2 DisableFirefoxDownloads
		$a_01_2 = {74 00 63 00 70 00 3a 00 2f 00 2f 00 32 00 2e 00 74 00 63 00 70 00 2e 00 65 00 75 00 2e 00 6e 00 67 00 72 00 6f 00 6b 00 2e 00 69 00 6f 00 } //2 tcp://2.tcp.eu.ngrok.io
		$a_01_3 = {24 30 32 38 64 30 34 32 31 2d 30 36 38 35 2d 34 30 63 33 2d 39 62 33 66 2d 30 32 64 66 66 62 31 39 34 37 65 62 } //2 $028d0421-0685-40c3-9b3f-02dffb1947eb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}