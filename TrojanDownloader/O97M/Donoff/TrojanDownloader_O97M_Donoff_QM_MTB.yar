
rule TrojanDownloader_O97M_Donoff_QM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {28 22 4d 53 58 22 20 26 20 22 4d 4c 32 22 20 26 20 22 2e 58 22 20 26 20 22 4d 4c 48 22 20 26 20 22 54 54 50 22 29 } //1 ("MSX" & "ML2" & ".X" & "MLH" & "TTP")
		$a_01_1 = {41 72 72 61 79 28 4e 69 63 2e 49 50 41 64 64 72 65 73 73 28 30 29 2c 20 43 6f 6d 70 75 74 65 72 4e 61 6d 65 29 } //1 Array(Nic.IPAddress(0), ComputerName)
		$a_01_2 = {47 65 74 49 50 5f 32 28 29 } //1 GetIP_2()
		$a_01_3 = {53 75 62 20 43 61 6c 63 4d 65 74 72 69 63 73 28 29 } //1 Sub CalcMetrics()
		$a_01_4 = {42 75 69 6c 64 50 72 6f 70 53 74 72 69 6e 67 } //1 BuildPropString
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}