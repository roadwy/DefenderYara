
rule TrojanDownloader_Win32_Carberp_BO{
	meta:
		description = "TrojanDownloader:Win32/Carberp.BO,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {88 46 0e 8a 43 0f 32 47 0f 88 46 0f 83 c3 10 83 c6 10 83 c1 10 8d 41 0f } //1
		$a_03_1 = {b9 ff 09 00 00 33 c0 8d bd fd d7 ff ff f3 ab 66 ab aa 68 00 28 00 00 6a 00 68 ?? ?? ?? ?? e8 ec 28 00 00 83 c4 0c 68 00 28 00 00 6a 00 } //1
		$a_03_2 = {31 ee 0f b6 ee 0f b6 2c ed ?? ?? ?? ?? c1 e5 08 31 ee 0f b6 ef 0f b6 2c ed ?? ?? ?? ?? c1 e5 18 31 ee 0f b6 ea 0f b6 2c ed ?? ?? ?? ?? 31 ef 0f b6 ec 0f b6 2c ed ?? ?? ?? ?? c1 e5 08 31 ef } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*10) >=11
 
}