
rule TrojanDownloader_Win32_Vundo_HJA{
	meta:
		description = "TrojanDownloader:Win32/Vundo.HJA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 40 10 8b 04 85 c8 3e 01 01 8a 00 88 45 c0 a1 b0 3e 01 01 03 05 2c 36 01 01 8a 00 32 45 c0 8b 0d b0 3e 01 01 03 0d 2c 36 01 01 88 01 e9 99 fe ff ff } //1
		$a_01_1 = {e8 37 35 00 00 e8 9a 5c ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}