
rule TrojanDownloader_O97M_Qakbot_FIL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.FIL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 74 69 65 73 74 61 2e 69 6e 2f 64 73 2f 32 39 31 31 32 30 2e 67 69 66 } //01 00  https://tiesta.in/ds/291120.gif
		$a_01_1 = {68 74 74 70 3a 2f 2f 65 78 70 61 6e 64 63 70 61 2e 63 6f 6d 2f 64 73 2f 32 39 31 31 32 30 2e 67 69 66 } //01 00  http://expandcpa.com/ds/291120.gif
		$a_01_2 = {68 74 74 70 3a 2f 2f 76 79 74 79 61 7a 68 6b 69 2e 62 79 2f 64 73 2f 32 39 31 31 32 30 2e 67 69 66 } //01 00  http://vytyazhki.by/ds/291120.gif
		$a_01_3 = {68 74 74 70 3a 2f 2f 62 61 67 72 6f 76 65 72 2e 63 6f 6d 2f 64 73 2f 32 39 31 31 32 30 2e 67 69 66 } //01 00  http://bagrover.com/ds/291120.gif
		$a_01_4 = {68 74 74 70 3a 2f 2f 62 75 6d 6b 61 2e 63 6f 6d 2e 75 61 2f 64 73 2f 32 39 31 31 32 30 2e 67 69 66 } //01 00  http://bumka.com.ua/ds/291120.gif
		$a_01_5 = {68 74 74 70 73 3a 2f 2f 61 75 72 6f 72 61 74 64 2e 63 66 2f 64 73 2f 32 39 31 31 32 30 2e 67 69 66 } //01 00  https://auroratd.cf/ds/291120.gif
		$a_01_6 = {68 74 74 70 3a 2f 2f 64 65 76 2e 7a 65 6d 70 2e 63 6f 6d 2f 64 73 2f 32 39 31 31 32 30 2e 67 69 66 } //01 00  http://dev.zemp.com/ds/291120.gif
		$a_01_7 = {68 74 74 70 3a 2f 2f 6d 69 63 6d 61 72 74 2e 73 74 6f 72 65 2f 64 73 2f 32 39 31 31 32 30 2e 67 69 66 } //01 00  http://micmart.store/ds/291120.gif
		$a_01_8 = {68 74 74 70 73 3a 2f 2f 76 69 72 61 75 67 72 61 2e 63 6f 6d 2f 64 73 2f 32 39 31 31 32 30 2e 67 69 66 } //01 00  https://viraugra.com/ds/291120.gif
		$a_01_9 = {68 74 74 70 73 3a 2f 2f 6e 79 75 73 63 61 70 65 2e 78 79 7a 2f 64 73 2f 32 39 31 31 32 30 2e 67 69 66 } //01 00  https://nyuscape.xyz/ds/291120.gif
		$a_01_10 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}