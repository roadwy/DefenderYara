
rule TrojanDownloader_Win32_Fugrafa_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Fugrafa.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 83 7a 14 10 8b c2 53 56 57 8b f1 72 02 8b 02 83 7e 14 10 72 02 8b 0e 8b 5a 10 8d 56 10 8b 3a 53 50 89 55 fc 8b d7 51 ?? ?? ?? ?? ?? 8b d0 83 c4 0c 83 fa ff 74 30 3b fa 72 33 8b c7 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}