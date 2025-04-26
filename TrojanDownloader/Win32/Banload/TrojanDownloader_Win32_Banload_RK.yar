
rule TrojanDownloader_Win32_Banload_RK{
	meta:
		description = "TrojanDownloader:Win32/Banload.RK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 73 65 72 50 72 6f 66 69 6c 65 [0-40] ff ff ff ff 03 00 00 00 65 78 65 00 ff ff ff ff 03 00 00 00 70 6e 67 00 } //1
		$a_01_1 = {ff 83 c3 08 4e 0f 85 d3 fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}