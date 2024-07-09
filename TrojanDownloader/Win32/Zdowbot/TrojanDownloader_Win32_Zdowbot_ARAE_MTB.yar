
rule TrojanDownloader_Win32_Zdowbot_ARAE_MTB{
	meta:
		description = "TrojanDownloader:Win32/Zdowbot.ARAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 fe ff 74 2f 6a 00 6a 00 ff d7 8b 0d ?? ?? ?? ?? b8 ?? ?? ?? ?? f7 ee c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 a1 ?? ?? ?? ?? 03 d2 2b c2 8a 14 30 30 14 31 46 3b 35 ?? ?? ?? ?? 72 c3 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}