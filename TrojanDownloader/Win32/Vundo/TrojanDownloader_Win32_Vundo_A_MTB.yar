
rule TrojanDownloader_Win32_Vundo_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Vundo.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 44 24 0c c7 44 24 0c 28 01 00 00 50 53 e8 ?? 22 00 00 85 c0 74 ?? 8b b4 24 38 01 00 00 8b 3d 58 70 00 10 8d 4c 24 30 56 51 ff ?? 85 c0 74 ?? 8d 54 24 0c 52 53 e8 ?? 22 00 00 85 c0 74 ?? 8d 44 24 30 56 50 ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}