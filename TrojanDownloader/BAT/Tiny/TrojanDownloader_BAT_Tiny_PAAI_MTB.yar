
rule TrojanDownloader_BAT_Tiny_PAAI_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.PAAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 00 69 00 6b 00 69 00 76 00 70 00 72 00 69 00 76 00 61 00 74 00 65 00 73 00 2e 00 37 00 6d 00 2e 00 70 00 6c 00 2f 00 64 00 61 00 74 00 61 00 62 00 61 00 73 00 65 00 2f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2f 00 6c 00 6f 00 70 00 69 00 6b 00 2e 00 65 00 78 00 65 00 } //01 00  nikivprivates.7m.pl/database/config/lopik.exe
		$a_01_1 = {43 00 3a 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 66 00 61 00 74 00 2e 00 65 00 78 00 65 00 } //00 00  C:\systemfat.exe
	condition:
		any of ($a_*)
 
}