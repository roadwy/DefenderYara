
rule TrojanSpy_Win32_Bancos_ABN{
	meta:
		description = "TrojanSpy:Win32/Bancos.ABN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5b 76 6d 6f 64 75 6c 6f } //1 [vmodulo
		$a_00_1 = {6b 75 6e 64 6f 72 6f 00 } //1 畫摮牯o
		$a_00_2 = {6c 75 67 61 72 6a 70 67 00 } //1
		$a_00_3 = {5b 53 65 6e 68 61 5d 00 } //1 卛湥慨]
		$a_01_4 = {89 45 e8 8b 45 e8 85 c0 74 05 83 e8 04 8b 00 83 f8 03 7d 2a 8d 55 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}