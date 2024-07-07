
rule TrojanDownloader_Win32_Zdowbot_ARAD_MTB{
	meta:
		description = "TrojanDownloader:Win32/Zdowbot.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 c9 7c 29 8b 35 88 ec 40 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 04 80 03 c0 8b d1 2b d0 8a 82 48 b3 40 00 30 04 0e 41 3b 0d 94 ec 40 00 72 ca } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}