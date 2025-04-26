
rule TrojanDownloader_Win32_Phorpiex_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Phorpiex.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 28 8b ff 32 5c 34 ?? 8d 4c 24 ?? 46 8d 79 ?? 8d 64 24 ?? 8a 11 41 84 d2 } //4
		$a_03_1 = {88 1c 28 8a 14 28 f6 d2 8b c8 88 14 28 45 8d 71 ?? 8b ff 8a 11 41 84 d2 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2) >=6
 
}