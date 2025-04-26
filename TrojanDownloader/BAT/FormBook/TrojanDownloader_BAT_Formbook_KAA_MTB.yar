
rule TrojanDownloader_BAT_Formbook_KAA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Formbook.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 31 00 39 00 32 00 2e 00 32 00 32 00 37 00 2e 00 31 00 38 00 33 00 2e 00 31 00 37 00 30 00 2f 00 6d 00 61 00 63 00 2f 00 } //2 ://192.227.183.170/mac/
		$a_01_1 = {56 00 63 00 78 00 78 00 64 00 74 00 61 00 7a 00 70 00 72 00 6c 00 2e 00 52 00 67 00 65 00 7a 00 6c 00 62 00 6b 00 77 00 78 00 71 00 72 00 7a 00 7a 00 64 00 67 00 6b 00 65 00 72 00 } //2 Vcxxdtazprl.Rgezlbkwxqrzzdgker
		$a_01_2 = {57 00 71 00 77 00 62 00 63 00 6b 00 74 00 69 00 } //2 Wqwbckti
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}