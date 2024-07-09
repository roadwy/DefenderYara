
rule TrojanDownloader_Win32_Spycos_D{
	meta:
		description = "TrojanDownloader:Win32/Spycos.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 3d 16 04 74 20 8d 95 ?? fe ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff } //1
		$a_03_1 = {b9 40 0d 03 00 5a e8 ?? ?? ff ff 84 c0 0f 84 } //1
		$a_03_2 = {6a 00 53 8d 55 e8 b9 10 00 00 00 8b 45 fc e8 ?? ?? ?? ff 33 c0 5a 59 59 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}