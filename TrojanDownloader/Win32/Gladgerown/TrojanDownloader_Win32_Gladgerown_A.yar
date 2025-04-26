
rule TrojanDownloader_Win32_Gladgerown_A{
	meta:
		description = "TrojanDownloader:Win32/Gladgerown.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 55 fc 83 ea 04 89 55 fc 8b 45 fc 3b 45 08 72 12 8b 4d fc 8b 11 81 f2 71 01 10 17 8b 45 fc 89 10 eb dd } //1
		$a_03_1 = {6a 10 8b 55 ?? 83 c2 38 52 8b 45 ?? 8b 48 30 51 e8 ?? ?? 00 00 85 c0 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}