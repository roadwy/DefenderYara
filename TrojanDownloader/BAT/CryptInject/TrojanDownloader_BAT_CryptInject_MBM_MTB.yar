
rule TrojanDownloader_BAT_CryptInject_MBM_MTB{
	meta:
		description = "TrojanDownloader:BAT/CryptInject.MBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 8e 69 5d 91 02 7b 90 01 01 00 00 04 07 91 61 d2 6f 90 01 01 00 00 0a 17 2c b0 07 17 25 2c 0e 90 00 } //01 00 
		$a_01_1 = {5a 00 78 00 63 00 68 00 61 00 71 00 6f 00 6c 00 6b 00 70 00 2e 00 46 00 68 00 78 00 6e 00 73 00 6b 00 61 00 } //01 00 
		$a_81_2 = {56 69 77 73 72 67 78 7a 65 76 } //00 00 
	condition:
		any of ($a_*)
 
}