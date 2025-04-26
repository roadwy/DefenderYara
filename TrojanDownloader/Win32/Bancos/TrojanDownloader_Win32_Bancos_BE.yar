
rule TrojanDownloader_Win32_Bancos_BE{
	meta:
		description = "TrojanDownloader:Win32/Bancos.BE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 70 64 61 74 65 00 0d 01 07 00 55 70 64 61 74 65 73 00 } //1
		$a_00_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 } //1 \system32\drivers\etc\hosts
		$a_00_2 = {3f 00 6e 00 61 00 6d 00 65 00 3d 00 00 00 } //1
		$a_00_3 = {77 00 69 00 6e 00 64 00 69 00 72 00 } //1 windir
		$a_01_4 = {6d 49 6e 46 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}