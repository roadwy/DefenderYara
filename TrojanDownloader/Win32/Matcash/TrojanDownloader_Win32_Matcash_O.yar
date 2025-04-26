
rule TrojanDownloader_Win32_Matcash_O{
	meta:
		description = "TrojanDownloader:Win32/Matcash.O,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {46 68 b9 79 37 9e 68 ?? ?? ?? ?? 57 e8 ?? ?? ff ff 83 c4 0c 83 c7 08 4e 75 e7 } //1
		$a_03_1 = {81 fe 00 00 10 00 75 ?? 57 e8 ?? ?? ff ff [0-10] 3b c7 59 74 02 ff d0 57 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}