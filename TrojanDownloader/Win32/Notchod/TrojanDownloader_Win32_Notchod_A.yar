
rule TrojanDownloader_Win32_Notchod_A{
	meta:
		description = "TrojanDownloader:Win32/Notchod.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 30 40 8a 10 32 f2 88 33 43 40 41 3b 4d 0c 72 ef } //1
		$a_03_1 = {68 fa 00 00 00 ff 15 90 01 04 68 05 01 00 00 6a 40 ff 15 90 01 04 89 45 fc 68 04 01 00 00 ff 75 fc 68 90 01 04 e8 90 01 04 ff 75 fc 6a 00 6a 00 ff 75 fc ff 15 90 01 04 6a 00 6a 00 ff 75 fc ff 75 08 6a 00 ff 90 01 05 ff 45 f8 0b c0 74 08 83 7d f8 04 73 02 eb a2 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}