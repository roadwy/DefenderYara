
rule TrojanDownloader_Win32_Vundo_HJB{
	meta:
		description = "TrojanDownloader:Win32/Vundo.HJB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 40 10 8b 04 85 40 3e 01 01 8a 00 88 45 d8 a1 28 3e 01 01 03 05 8c 35 01 01 8a 00 32 45 d8 8b 0d 28 3e 01 01 03 0d 8c 35 01 01 88 01 e9 8c fe ff ff } //1
		$a_01_1 = {e8 79 3c 00 00 e8 1d 5c ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}