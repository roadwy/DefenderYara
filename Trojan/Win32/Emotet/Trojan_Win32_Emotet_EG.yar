
rule Trojan_Win32_Emotet_EG{
	meta:
		description = "Trojan:Win32/Emotet.EG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 "
		
	strings :
		$a_01_0 = {68 77 69 74 68 75 70 64 61 74 65 73 2e 33 34 20 47 6f 6f 67 6c 65 20 44 6f 77 6e 6c 6f 61 64 65 20 64 6f 6e 65 20 43 36 20 63 6f 6f 72 64 69 6e 61 74 65 64 20 70 61 73 73 61 67 65 } //1 hwithupdates.34 Google Downloade done C6 coordinated passage
		$a_01_1 = {61 66 74 65 72 20 69 6e 73 74 61 6e 63 65 20 73 74 61 62 6c 65 20 44 72 6f 70 62 6f 78 20 45 61 73 74 65 72 20 61 76 61 69 6c 61 62 6c 65 20 76 69 72 74 75 61 6c 2c 66 69 72 73 74 } //1 after instance stable Dropbox Easter available virtual,first
		$a_01_2 = {64 65 76 65 6c 6f 70 65 72 73 2c 64 74 79 68 35 33 34 35 65 34 72 } //1 developers,dtyh5345e4r
		$a_01_3 = {61 6e 6e 6f 75 6e 63 65 64 77 61 73 54 28 62 61 73 65 64 53 65 65 6c 61 73 74 74 74 68 75 6d 62 6e 61 69 6c 73 58 50 } //1 announcedwasT(basedSeelasttthumbnailsXP
		$a_01_4 = {4f 50 61 72 74 69 61 6c 72 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 47 72 61 6e 67 65 72 73 47 6f 6f 67 6c 65 6f 6e 72 65 70 72 65 73 65 6e 74 } //1 OPartialrinstallationGrangersGoogleonrepresent
		$a_01_5 = {6f 70 65 6e 2e 53 39 72 65 66 65 72 73 79 76 75 6c 6e 65 72 61 62 69 6c 69 74 69 65 73 2e 6d 65 73 73 61 67 65 7a 77 61 6c 6b 65 72 53 } //1 open.S9refersyvulnerabilities.messagezwalkerS
		$a_01_6 = {42 65 74 61 67 70 72 65 64 69 63 74 69 6f 6e 73 31 31 31 61 74 61 79 6c 6f 72 52 5a 66 69 72 73 74 } //1 Betagpredictions111ataylorRZfirst
		$a_01_7 = {77 65 62 65 78 63 6c 75 73 69 6f 6e 75 73 65 64 72 65 66 6c 65 63 74 73 49 6e 74 65 72 6e 65 74 61 6c 6c 6f 77 73 55 70 64 61 74 65 6f 66 66 65 72 } //1 webexclusionusedreflectsInternetallowsUpdateoffer
		$a_01_8 = {6e 65 77 56 68 73 79 6e 63 68 72 6f 6e 69 7a 61 74 69 6f 6e 30 6e 74 68 65 70 72 65 76 69 6f 75 73 6c 79 36 74 68 65 } //1 newVhsynchronization0nthepreviously6the
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=3
 
}