
rule Adware_MacOS_Pirrit_B{
	meta:
		description = "Adware:MacOS/Pirrit.B,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 73 6c 65 65 70 46 6f 72 54 69 6d 65 49 6e 74 65 72 76 61 6c 3a } //1 jsleepForTimeInterval:
		$a_01_1 = {25 6a 39 7d 6f 51 } //1 %j9}oQ
		$a_01_2 = {4d 32 3c 50 77 63 3a } //1 M2<Pwc:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Adware_MacOS_Pirrit_B_2{
	meta:
		description = "Adware:MacOS/Pirrit.B,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 69 72 72 69 74 2e 63 6f 6d } //2 pirrit.com
		$a_00_1 = {50 69 72 72 69 74 53 75 67 67 65 73 74 6f 72 } //2 PirritSuggestor
		$a_00_2 = {74 2e 74 72 6b 69 74 6f 6b 2e 63 6f 6d 2f 74 72 61 63 6b 2f 72 65 70 } //1 t.trkitok.com/track/rep
		$a_00_3 = {56 53 65 61 72 63 68 2e 66 72 61 6d 65 77 6f 72 6b } //1 VSearch.framework
		$a_00_4 = {64 65 6c 74 61 2d 73 65 61 72 63 68 2e 63 6f 6d } //1 delta-search.com
		$a_00_5 = {42 72 6f 77 73 65 72 45 6e 68 61 6e 63 65 72 } //1 BrowserEnhancer
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}