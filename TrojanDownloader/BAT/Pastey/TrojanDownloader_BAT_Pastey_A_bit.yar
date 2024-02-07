
rule TrojanDownloader_BAT_Pastey_A_bit{
	meta:
		description = "TrojanDownloader:BAT/Pastey.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 00 61 00 73 00 74 00 65 00 2e 00 65 00 65 00 2f 00 72 00 2f 00 58 00 79 00 4d 00 44 00 49 00 } //01 00  paste.ee/r/XyMDI
		$a_01_1 = {4f 00 6c 00 70 00 76 00 62 00 6d 00 55 00 75 00 53 00 57 00 52 00 6c 00 62 00 6e 00 52 00 70 00 5a 00 6d 00 6c 00 6c 00 63 00 67 00 3d 00 3d 00 } //01 00  OlpvbmUuSWRlbnRpZmllcg==
		$a_01_2 = {56 00 31 00 4e 00 6a 00 63 00 6d 00 6c 00 77 00 64 00 43 00 35 00 54 00 61 00 47 00 56 00 73 00 62 00 41 00 3d 00 3d 00 } //01 00  V1NjcmlwdC5TaGVsbA==
		$a_01_3 = {55 00 33 00 52 00 68 00 63 00 6e 00 52 00 31 00 63 00 41 00 3d 00 3d 00 } //00 00  U3RhcnR1cA==
	condition:
		any of ($a_*)
 
}