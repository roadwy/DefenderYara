
rule TrojanDownloader_BAT_Ranos_A{
	meta:
		description = "TrojanDownloader:BAT/Ranos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {62 61 6e 6b 69 6e 67 63 61 6c 2e 52 65 73 6f 75 72 63 65 73 } //bankingcal.Resources  01 00 
		$a_80_1 = {74 6e 69 6f 50 79 72 74 6e 45 } //tnioPyrtnE  01 00 
		$a_80_2 = {68 74 74 70 73 6c 6f 67 69 6e } //httpslogin  01 00 
		$a_80_3 = {4e 6f 77 20 45 78 65 63 75 74 69 6e 67 20 43 75 73 74 6f 6d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 2e 2e } //Now Executing Custom Application...  00 00 
		$a_00_4 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}