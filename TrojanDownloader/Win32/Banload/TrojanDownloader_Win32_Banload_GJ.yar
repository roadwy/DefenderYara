
rule TrojanDownloader_Win32_Banload_GJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.GJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {e8 9f 47 fa ff 6a 05 68 ?? ?? ?? ?? e8 93 47 fa ff 6a 05 68 ?? ?? ?? ?? e8 87 47 fa ff 6a 05 68 ?? ?? ?? ?? e8 7b 47 fa ff } //1
		$a_01_1 = {33 c9 51 51 51 51 51 51 51 51 53 8b d8 33 c0 } //1
		$a_00_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 69 00 73 00 63 00 6f 00 76 00 69 00 72 00 74 00 75 00 61 00 6c 00 2e 00 74 00 65 00 72 00 72 00 61 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 76 00 64 00 6d 00 61 00 69 00 6e 00 2e 00 73 00 68 00 74 00 6d 00 6c 00 } //1 http://discovirtual.terra.com.br/vdmain.shtml
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}