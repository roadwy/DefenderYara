
rule Trojan_BAT_Rhadamanthys_SPS_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.SPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {55 45 73 44 42 42 51 41 41 41 41 49 41 4a 71 44 59 31 72 4a 76 75 2b 69 38 53 6b 4b 41 41 41 45 44 41 41 48 41 41 41 41 5a 7a 4a 74 4c 6d 52 73 62 4f 78 61 66 58 67 54 56 62 6f 2f 30 77 36 51 30 73 41 45 43 46 41 42 6f 55 68 33 6c 55 58 35 55 4b 34 72 56 31 78 62 6c 73 48 71 4d } //1 UEsDBBQAAAAIAJqDY1rJvu+i8SkKAAAEDAAHAAAAZzJtLmRsbOxafXgTVbo/0w6Q0sAECFABoUh3lUX5UK4rV1xblsHqM
		$a_01_1 = {72 64 68 61 2e 65 78 65 } //1 rdha.exe
		$a_81_2 = {45 78 74 72 61 63 74 65 64 5a 69 70 5f 31 63 66 36 30 37 33 34 5c 70 61 63 6b 61 67 65 } //1 ExtractedZip_1cf60734\package
		$a_01_3 = {67 32 6d 2e 64 6c 6c } //1 g2m.dll
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}