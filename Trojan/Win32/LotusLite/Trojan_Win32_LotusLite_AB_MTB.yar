
rule Trojan_Win32_LotusLite_AB_MTB{
	meta:
		description = "Trojan:Win32/LotusLite.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 "
		
	strings :
		$a_81_0 = {31 37 32 2e 38 31 2e 36 30 2e 39 37 } //6 172.81.60.97
		$a_81_1 = {47 6c 6f 62 61 6c 5c 54 65 63 68 6e 6f 6c 6f 67 79 33 36 30 2d 41 40 50 40 54 2d 54 65 61 6d } //6 Global\Technology360-A@P@T-Team
		$a_81_2 = {44 61 74 61 49 6d 70 6f 72 74 65 72 4d 61 69 6e } //4 DataImporterMain
		$a_81_3 = {6b 75 67 6f 75 2e 64 6c 6c } //4 kugou.dll
		$a_81_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_81_5 = {4b 75 67 6f 75 4d 61 69 6e } //1 KugouMain
	condition:
		((#a_81_0  & 1)*6+(#a_81_1  & 1)*6+(#a_81_2  & 1)*4+(#a_81_3  & 1)*4+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=22
 
}