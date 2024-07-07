
rule TrojanDownloader_Win32_Adload_DL_bit{
	meta:
		description = "TrojanDownloader:Win32/Adload.DL!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 b4 05 b0 fb ff ff 54 40 83 f8 0b 72 f2 } //1
		$a_01_1 = {80 b4 05 b0 fb ff ff 54 40 83 f8 0f 72 f2 } //1
		$a_01_2 = {80 b4 05 50 fb ff ff 54 40 83 f8 11 72 f2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}