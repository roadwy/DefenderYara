
rule TrojanDownloader_Win32_Spycos_G{
	meta:
		description = "TrojanDownloader:Win32/Spycos.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {22 20 2d 75 90 09 1c 00 0d 00 00 00 72 65 67 73 76 72 33 32 20 2f 73 20 22 00 00 00 ff ff ff ff 04 00 00 00 } //1
		$a_03_1 = {22 20 2d 75 00 00 00 00 ff ff ff ff 06 00 00 00 41 43 20 52 45 47 00 90 09 0e 00 3d 3d 00 00 00 00 ff ff ff ff 04 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}