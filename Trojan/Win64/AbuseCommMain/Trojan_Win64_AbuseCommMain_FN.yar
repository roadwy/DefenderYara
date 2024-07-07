
rule Trojan_Win64_AbuseCommMain_FN{
	meta:
		description = "Trojan:Win64/AbuseCommMain.FN,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 00 6f 00 78 00 3a 00 33 00 36 00 46 00 31 00 38 00 36 00 43 00 36 00 46 00 44 00 43 00 41 00 41 00 43 00 30 00 43 00 46 00 31 00 32 00 32 00 45 00 32 00 33 00 34 00 42 00 35 00 44 00 31 00 35 00 46 00 33 00 46 00 34 00 32 00 46 00 37 00 33 00 35 00 36 00 38 00 37 00 34 00 35 00 46 00 32 00 35 00 31 00 43 00 31 00 33 00 30 00 36 00 44 00 37 00 31 00 45 00 42 00 43 00 41 00 39 00 36 00 38 00 31 00 37 00 } //1 tox:36F186C6FDCAAC0CF122E234B5D15F3F42F73568745F251C1306D71EBCA96817
		$a_02_1 = {33 36 46 31 38 36 43 36 46 44 43 41 41 43 30 43 46 31 32 32 45 32 33 34 42 35 44 31 35 46 33 46 34 32 46 37 33 35 36 38 37 34 35 46 32 35 31 43 31 33 30 36 44 37 31 45 42 43 41 39 36 38 31 37 90 01 0c 00 00 00 00 4c 00 00 00 00 00 00 00 90 00 } //1
		$a_02_2 = {33 36 46 31 38 36 43 36 46 44 43 41 41 43 30 43 46 31 32 32 45 32 33 34 42 35 44 31 35 46 33 46 34 32 46 37 33 35 36 38 37 34 35 46 32 35 31 43 31 33 30 36 44 37 31 45 42 43 41 39 36 38 31 37 90 01 0c 4c 00 00 00 90 00 } //1
		$a_00_3 = {5c 74 6f 78 5c 33 36 46 31 38 36 43 36 46 44 43 41 41 43 30 43 46 31 32 32 45 32 33 34 42 35 44 31 35 46 33 46 34 32 46 37 33 35 36 38 37 34 35 46 32 35 31 43 31 33 30 36 44 37 31 45 42 43 41 39 36 38 31 37 2e 68 73 74 72 } //1 \tox\36F186C6FDCAAC0CF122E234B5D15F3F42F73568745F251C1306D71EBCA96817.hstr
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=1
 
}