
rule TrojanDownloader_Win32_Upiner_A{
	meta:
		description = "TrojanDownloader:Win32/Upiner.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 67 65 74 2e 61 73 70 3f 6d 61 63 3d 00 } //1 术瑥愮灳洿捡=
		$a_01_1 = {26 61 76 73 3d 75 6e 6b 6e 6f 77 26 70 73 3d 4e 4f } //1 &avs=unknow&ps=NO
		$a_01_2 = {75 6e 5c 59 6f 75 50 69 6e } //1 un\YouPin
		$a_01_3 = {37 38 36 34 36 34 36 30 32 41 33 46 33 46 } //1 786464602A3F3F
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}