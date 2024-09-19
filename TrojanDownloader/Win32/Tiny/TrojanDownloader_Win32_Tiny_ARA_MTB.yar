
rule TrojanDownloader_Win32_Tiny_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tiny.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f4 03 4d fc 8b 95 64 ff ff ff 8b 45 fc 8a 84 05 ac fa ff ff 88 04 0a e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}