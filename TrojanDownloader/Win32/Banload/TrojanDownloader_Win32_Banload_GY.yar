
rule TrojanDownloader_Win32_Banload_GY{
	meta:
		description = "TrojanDownloader:Win32/Banload.GY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {ff ff ff ff 10 00 00 00 39 38 33 34 39 32 42 38 44 32 36 46 45 35 30 37 00 00 00 00 ff ff ff ff 01 00 00 00 44 00 00 00 } //1
		$a_02_1 = {70 70 70 33 2e 67 69 66 90 05 08 01 00 6f 70 65 6e 00 00 00 00 ff ff ff ff 90 01 01 00 00 00 90 02 09 2e 73 63 72 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}