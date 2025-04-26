
rule TrojanDownloader_O97M_Powdow_RVB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 28 33 34 29 20 26 20 22 68 74 74 70 3a 2f 2f 32 30 39 2e 31 34 31 2e 36 31 2e 31 32 34 2f 51 2d 32 2f 66 73 6f 6c 65 41 70 70 31 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 } //1 Chr(34) & "http://209.141.61.124/Q-2/fsoleApp1.ex" & Chr(101)
		$a_01_1 = {61 6c 73 6f 74 72 75 65 20 3d 20 22 70 6f 77 65 72 73 22 0d 0a 74 68 69 6e 67 62 6f 78 20 3d 20 22 68 65 6c 6c 22 } //1 污潳牴敵㴠∠潰敷獲ഢ琊楨杮潢⁸‽栢汥≬
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4f 75 74 6c 6f 6f 6b 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 CreateObject("Outlook.Application")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}