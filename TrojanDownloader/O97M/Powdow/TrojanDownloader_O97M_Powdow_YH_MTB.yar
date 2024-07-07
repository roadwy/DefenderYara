
rule TrojanDownloader_O97M_Powdow_YH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.YH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4b 6f 6c 65 73 74 65 72 2e 76 62 73 22 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 } //1 C:\ProgramData\Kolester.vbs" For Binary As
		$a_01_1 = {4f 70 65 6e 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 48 65 6c 70 6f 74 2e 76 62 73 22 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 } //1 Open "C:\ProgramData\Helpot.vbs" For Binary As
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 4b 6f 70 65 72 74 2e 43 69 6c 6f 74 65 72 } //1 CreateObject(Kopert.Ciloter
		$a_01_3 = {42 72 65 6d 65 6e 2e 45 78 65 63 20 4b 6f 70 65 72 74 2e 43 69 6c 6f 74 65 72 } //1 Bremen.Exec Kopert.Ciloter
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}