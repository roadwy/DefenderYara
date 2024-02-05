
rule Trojan_Win64_Dridex_DB_MTB{
	meta:
		description = "Trojan:Win64/Dridex.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {42 6f 66 66 6f 72 5a 69 6e 64 61 73 68 65 73 } //BofforZindashes  03 00 
		$a_80_1 = {7a 57 76 4d 61 79 65 6e 74 65 72 73 74 6f 32 30 31 32 2c 61 6c 74 68 6f 75 67 68 4e 65 77 } //zWvMayentersto2012,althoughNew  03 00 
		$a_80_2 = {77 70 6c 75 67 69 6e 73 6d 61 72 6b 65 74 71 6f 6e 72 65 63 75 72 73 69 6f 6e 2d 74 72 61 63 69 6e 67 6a } //wpluginsmarketqonrecursion-tracingj  03 00 
		$a_80_3 = {37 37 37 37 37 37 37 37 38 4a 62 72 6f 77 73 65 72 73 2e 36 32 34 } //777777778Jbrowsers.624  03 00 
		$a_80_4 = {46 69 6e 64 46 69 72 73 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 57 } //FindFirstUrlCacheEntryW  03 00 
		$a_80_5 = {49 6e 69 74 69 61 74 65 53 79 73 74 65 6d 53 68 75 74 64 6f 77 6e 57 } //InitiateSystemShutdownW  03 00 
		$a_80_6 = {47 65 74 53 69 64 4c 65 6e 67 74 68 52 65 71 75 69 72 65 64 } //GetSidLengthRequired  00 00 
	condition:
		any of ($a_*)
 
}