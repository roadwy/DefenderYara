
rule TrojanDownloader_O97M_Donoff_CB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CB,SIGNATURE_TYPE_MACROHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 43 68 72 28 33 37 29 20 2b 20 43 68 72 28 38 34 29 20 2b 20 43 68 72 28 37 37 29 20 2b 20 43 68 72 28 38 30 29 20 } //3 .ExpandEnvironmentStrings(Chr(37) + Chr(84) + Chr(77) + Chr(80) 
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 43 68 72 28 37 37 29 20 2b 20 43 68 72 28 31 30 35 29 20 2b 20 43 68 72 28 39 39 29 20 2b 20 43 68 72 28 31 31 34 29 20 2b 20 43 68 72 28 31 31 31 } //3 = CreateObject(Chr(77) + Chr(105) + Chr(99) + Chr(114) + Chr(111
		$a_01_2 = {2e 57 72 69 74 65 20 4f 52 50 56 45 4c 50 50 55 47 45 53 54 4a 4e 57 42 56 4c 49 4a 49 4b 44 47 4b 53 47 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } //3 .Write ORPVELPPUGESTJNWBVLIJIKDGKSG.responseBody
		$a_01_3 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 46 4e 49 4b 47 53 48 56 55 4d 47 51 4c 48 4f 54 4b 4b 45 45 52 56 43 51 5a 50 43 4b 2c 20 46 61 6c 73 65 } //4 .Open "GET", FNIKGSHVUMGQLHOTKKEERVCQZPCK, False
		$a_01_4 = {3d 20 43 68 72 28 41 73 63 28 4e 56 58 59 55 48 56 4c 44 42 56 47 42 56 44 49 5a 5a 54 4d 5a 4c 52 59 50 58 51 53 29 20 2d 20 } //3 = Chr(Asc(NVXYUHVLDBVGBVDIZZTMZLRYPXQS) - 
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4+(#a_01_4  & 1)*3) >=16
 
}