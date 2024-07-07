
rule TrojanDownloader_O97M_Ursnif_URC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.URC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 14 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 67 73 74 61 74 2e 6d 61 74 74 68 65 77 73 61 6c 65 6d 73 74 6f 6c 70 65 72 2e 63 6f 6d 2f 70 61 67 61 6d 65 6e 74 31 2e 65 78 65 } //1 http://gstat.matthewsalemstolper.com/pagament1.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 67 73 74 61 74 2e 61 75 73 61 67 69 73 74 6d 65 6e 74 2e 63 6f 6d 2f 70 61 67 61 6d 65 6e 74 31 2e 65 78 65 } //1 http://gstat.ausagistment.com/pagament1.exe
		$a_01_2 = {68 74 74 70 3a 2f 2f 67 73 74 61 74 2e 6c 6c 62 6e 74 76 2e 63 6f 6d 2f 70 61 67 61 6d 65 6e 74 31 2e 65 78 65 } //1 http://gstat.llbntv.com/pagament1.exe
		$a_01_3 = {68 74 74 70 3a 2f 2f 67 73 74 61 74 2e 6c 6c 62 6e 74 76 2e 6f 72 67 2f 70 61 67 61 6d 65 6e 74 31 2e 65 78 65 } //1 http://gstat.llbntv.org/pagament1.exe
		$a_01_4 = {68 74 74 70 73 3a 2f 2f 61 6e 72 38 2e 63 6f 6d 2e 61 75 2f 6c 6f 78 61 72 63 68 69 76 65 46 41 4c 53 45 73 69 67 6e 2e 70 68 70 } //1 https://anr8.com.au/loxarchiveFALSEsign.php
		$a_01_5 = {68 74 74 70 73 3a 2f 2f 79 79 61 75 74 6f 2e 63 6f 6d 2e 61 75 2f 73 65 74 74 69 6e 67 73 2f 62 6f 73 73 2e 70 68 70 } //1 https://yyauto.com.au/settings/boss.php
		$a_01_6 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 6c 6f 76 65 6b 6f 6c 61 63 68 65 73 2e 63 6f 6d 2f 64 6f 63 75 73 69 67 6e 2f 73 69 67 6e 2e 70 68 70 } //1 https://www.lovekolaches.com/docusign/sign.php
		$a_01_7 = {68 74 74 70 73 3a 2f 2f 74 6c 61 6e 64 64 69 73 73 69 70 61 74 65 2e 61 74 2f 33 2f 72 62 73 2e 64 6c 6c } //1 https://tlanddissipate.at/3/rbs.dll
		$a_01_8 = {68 74 74 70 3a 2f 2f 31 34 39 2e 32 38 2e 33 33 2e 38 30 2f 64 6f 63 75 6d 65 6e 74 73 2e 70 68 70 } //1 http://149.28.33.80/documents.php
		$a_01_9 = {68 74 74 70 3a 2f 2f 34 35 2e 36 33 2e 33 30 2e 32 30 2f 6c 31 6f 32 63 33 6f 34 6d 35 6f 36 74 37 69 38 76 2e 70 68 70 } //1 http://45.63.30.20/l1o2c3o4m5o6t7i8v.php
		$a_01_10 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 64 72 65 6c 61 74 65 6d 65 64 69 61 2e 63 6f 6d 2f 68 61 69 64 72 65 73 73 2f 67 6d 61 69 6c 2e 70 68 70 } //1 http://www.adrelatemedia.com/haidress/gmail.php
		$a_01_11 = {68 74 74 70 73 3a 2f 2f 6d 65 6d 62 65 72 74 65 61 6d 2e 77 6f 72 6b 73 2f 74 65 6d 70 6c 61 74 65 73 62 2f 73 75 70 65 72 74 68 65 6d 65 6e 2e 70 68 70 } //1 https://memberteam.works/templatesb/superthemen.php
		$a_01_12 = {68 74 74 70 3a 2f 2f 31 34 39 2e 32 38 2e 33 33 2e 38 30 2f 4f 44 5a 41 43 55 51 2e 65 78 65 } //1 http://149.28.33.80/ODZACUQ.exe
		$a_01_13 = {68 74 74 70 73 3a 2f 2f 65 6e 74 73 70 61 72 74 6e 65 72 2e 61 74 2f 33 2f 72 73 6b 2e 64 6c 6c } //1 https://entspartner.at/3/rsk.dll
		$a_01_14 = {68 74 74 70 73 3a 2f 2f 6f 67 67 6c 65 64 65 64 69 62 6c 2e 61 74 2f 33 2f 64 77 73 2e 64 6c 6c } //1 https://ogglededibl.at/3/dws.dll
		$a_01_15 = {68 74 74 70 73 3a 2f 2f 64 65 73 74 67 72 65 6e 61 2e 61 74 2f 33 2f 74 73 6b 2e 64 6c 6c } //1 https://destgrena.at/3/tsk.dll
		$a_01_16 = {68 74 74 70 73 3a 2f 2f 73 64 65 70 75 74 69 7a 69 2e 61 74 2f 33 2f 64 6f 6b 2e 64 6c 6c } //1 https://sdeputizi.at/3/dok.dll
		$a_01_17 = {68 74 74 70 73 3a 2f 2f 75 74 65 6e 74 69 2e 6f 6e 6c 69 6e 65 2f 31 2e 65 78 65 } //1 https://utenti.online/1.exe
		$a_01_18 = {68 74 74 70 73 3a 2f 2f 73 7a 6e 2e 73 65 72 76 69 63 65 73 2f 31 2e 65 78 65 } //1 https://szn.services/1.exe
		$a_01_19 = {68 74 74 70 73 3a 2f 2f 6e 6c 2e 6d 6a 6e 64 6f 6d 65 69 6e 2e 73 79 73 74 65 6d 73 2f 31 2e 65 78 65 } //1 https://nl.mjndomein.systems/1.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1) >=1
 
}