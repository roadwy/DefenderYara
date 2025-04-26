
rule TrojanDownloader_BAT_Pwsx_SB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Pwsx.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {73 74 69 6e 6b 61 72 64 73 20 70 6c 61 6e 75 6c 61 20 73 75 62 69 6e 64 65 78 65 73 } //1 stinkards planula subindexes
		$a_81_1 = {70 6f 70 70 61 20 74 61 6e 67 6c 65 73 20 72 69 74 75 61 6c 69 7a 61 74 69 6f 6e 73 } //1 poppa tangles ritualizations
		$a_81_2 = {73 74 65 6d 73 6f 6e 73 20 75 6e 73 68 69 70 70 65 64 20 6f 75 74 73 6d 6f 6b 65 73 } //1 stemsons unshipped outsmokes
		$a_81_3 = {24 33 37 35 63 35 65 66 66 2d 30 36 35 30 2d 34 33 30 31 2d 38 35 65 66 2d 33 38 32 63 66 65 66 61 39 61 64 66 } //2 $375c5eff-0650-4301-85ef-382cfefa9adf
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*2) >=5
 
}