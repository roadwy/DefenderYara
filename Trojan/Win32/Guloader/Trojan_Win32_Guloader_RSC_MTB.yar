
rule Trojan_Win32_Guloader_RSC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 4b 6c 69 70 70 65 73 70 61 6c 74 65 6e 73 36 37 5c 6d 65 74 6f 64 69 6b 65 72 65 6e 2e 74 61 78 } //1 \Klippespaltens67\metodikeren.tax
		$a_81_1 = {44 69 65 67 69 76 6e 69 6e 67 65 72 73 5c 64 65 63 65 6e 74 72 61 6c 69 73 65 72 69 6e 67 73 70 6f 6c 69 74 69 6b 6b 65 72 73 } //1 Diegivningers\decentraliseringspolitikkers
		$a_81_2 = {25 73 61 6e 74 69 61 67 6f 25 5c 61 66 73 79 6e 67 6e 69 6e 67 65 72 6e 65 } //1 %santiago%\afsyngningerne
		$a_81_3 = {25 42 6c 6f 6d 73 74 65 72 62 75 74 69 6b 6b 65 72 6e 65 73 25 5c 6f 76 65 72 62 65 62 79 67 67 65 6c 73 65 73 2e 6f 76 65 } //1 %Blomsterbutikkernes%\overbebyggelses.ove
		$a_81_4 = {39 39 5c 70 6f 70 6f 76 65 72 2e 69 6e 69 } //1 99\popover.ini
		$a_81_5 = {5c 4c 61 6e 67 66 69 62 72 65 64 65 2e 55 6e 74 } //1 \Langfibrede.Unt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}