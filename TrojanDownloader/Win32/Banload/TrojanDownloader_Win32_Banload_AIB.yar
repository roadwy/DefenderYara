
rule TrojanDownloader_Win32_Banload_AIB{
	meta:
		description = "TrojanDownloader:Win32/Banload.AIB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 73 76 72 33 32 20 2f 73 20 } //1 regsvr32 /s 
		$a_01_1 = {23 4c 23 00 ff ff ff ff 03 00 00 00 65 78 65 00 ff ff ff ff 0c 00 00 00 72 65 67 73 76 72 33 32 20 2f 73 20 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*4) >=5
 
}