
rule TrojanDownloader_O97M_XlmMacro_gen_DG{
	meta:
		description = "TrojanDownloader:O97M/XlmMacro.gen!DG,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 16 00 00 "
		
	strings :
		$a_01_0 = {41 6f 00 08 } //1 潁ࠀ
		$a_01_1 = {41 6f 00 03 } //1 潁̀
		$a_01_2 = {41 6f 00 04 } //1 潁Ѐ
		$a_01_3 = {42 01 06 80 } //1
		$a_01_4 = {42 02 60 80 } //1
		$a_01_5 = {42 01 60 80 } //1
		$a_01_6 = {42 01 11 80 } //1
		$a_01_7 = {42 01 6e 00 } //1 łn
		$a_01_8 = {42 07 95 00 } //1
		$a_01_9 = {42 06 96 00 } //1
		$a_01_10 = {42 07 96 00 } //1
		$a_01_11 = {42 08 96 00 } //1
		$a_01_12 = {42 09 96 00 } //1
		$a_01_13 = {08 41 01 01 } //1 䄈ā
		$a_03_14 = {08 17 01 00 [0-03] 00 08 17 01 00 [0-03] 00 08 17 01 00 90 0a 20 00 00 00 17 01 00 [0-03] 00 17 01 00 [0-03] 00 } //1
		$a_01_15 = {42 01 50 01 } //1 łŐ
		$a_01_16 = {42 02 50 01 } //1 ɂŐ
		$a_01_17 = {42 03 50 01 } //1 ͂Ő
		$a_01_18 = {42 04 50 01 } //1 тŐ
		$a_01_19 = {42 05 50 01 } //1 ՂŐ
		$a_01_20 = {42 06 50 01 } //1 قŐ
		$a_01_21 = {42 07 50 01 } //1 ݂Ő
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_03_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1) >=1
 
}