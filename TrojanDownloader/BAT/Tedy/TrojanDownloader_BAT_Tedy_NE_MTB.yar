
rule TrojanDownloader_BAT_Tedy_NE_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tedy.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 14 00 00 0a 25 72 01 00 00 70 6f 15 00 00 0a 25 17 6f 16 00 00 0a 25 72 17 00 00 70 6f 17 00 00 0a 28 18 00 00 0a 26 2a } //02 00 
		$a_01_1 = {45 00 54 00 48 00 20 00 43 00 4f 00 49 00 4e 00 74 00 2e 00 57 00 54 00 46 00 20 00 43 00 4f 00 49 00 4e 00 6c 00 49 00 4f 00 53 00 4e 00 54 00 } //02 00  ETH COINt.WTF COINlIOSNT
		$a_01_2 = {24 00 54 00 52 00 55 00 4d 00 50 00 } //00 00  $TRUMP
	condition:
		any of ($a_*)
 
}