
rule TrojanDownloader_Win32_Dogrobot_gen_J{
	meta:
		description = "TrojanDownloader:Win32/Dogrobot.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 30 0f be 34 1f 83 fe 20 7c 22 83 fe 7e 7f 1d e8 ?? ?? 00 00 8d 0c 40 c1 e1 05 8d 44 31 e0 b9 5f 00 00 00 99 f7 f9 80 c2 20 88 14 1f 47 3b fd 7c d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}