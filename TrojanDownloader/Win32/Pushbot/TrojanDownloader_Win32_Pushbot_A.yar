
rule TrojanDownloader_Win32_Pushbot_A{
	meta:
		description = "TrojanDownloader:Win32/Pushbot.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 6a 1a 59 f7 f9 83 c2 61 89 55 f8 8d 45 f8 50 ff 75 fc [0-20] 50 68 04 01 00 00 ff 15 ?? ?? ?? 00 6a 03 e8 ?? ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}