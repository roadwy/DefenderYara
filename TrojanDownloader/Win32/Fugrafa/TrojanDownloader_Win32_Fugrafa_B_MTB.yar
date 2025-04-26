
rule TrojanDownloader_Win32_Fugrafa_B_MTB{
	meta:
		description = "TrojanDownloader:Win32/Fugrafa.B!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 38 6a 00 8d 45 f8 c7 45 f8 00 00 00 00 50 ff 76 34 ff 76 28 57 } //1
		$a_01_1 = {55 8b ec 51 83 7a 14 10 8b c2 56 8b f1 89 75 fc 72 02 8b 02 ff 72 10 50 51 8b 4d 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}