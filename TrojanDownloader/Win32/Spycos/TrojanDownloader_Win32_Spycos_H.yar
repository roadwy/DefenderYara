
rule TrojanDownloader_Win32_Spycos_H{
	meta:
		description = "TrojanDownloader:Win32/Spycos.H,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {35 ae ca 7b c3 ff 25 ?? ?? ?? ?? 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 } //2
		$a_00_1 = {69 6e 6f 76 61 6e 64 6f 6f 6f 6f 2e 2e 2e } //1 inovandoooo...
		$a_00_2 = {74 69 70 6f 3d 00 } //1 楴潰=
		$a_03_3 = {50 6c 75 67 69 6e 20 52 45 44 2e 2e 2e 2e 2e 2e 3a 20 (53 49 4d|41 56 47 49 4e 48 4f) } //1
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}