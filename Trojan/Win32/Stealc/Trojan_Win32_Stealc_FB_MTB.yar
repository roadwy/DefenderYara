
rule Trojan_Win32_Stealc_FB_MTB{
	meta:
		description = "Trojan:Win32/Stealc.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5a 61 7a 65 20 78 75 68 6f 20 78 75 70 75 68 61 67 61 76 75 6d 75 20 62 65 6d 6f 7a 65 64 69 77 61 74 69 72 69 63 20 62 65 6b } //1 Zaze xuho xupuhagavumu bemozediwatiric bek
		$a_01_1 = {58 69 6c 6f 6d 69 6b 20 72 65 63 6f 66 75 77 65 73 65 74 69 64 75 70 20 76 61 73 69 66 69 73 6f 6b 20 62 65 7a 65 73 65 63 6f 6b 69 73 65 20 79 69 63 65 78 61 6a } //1 Xilomik recofuwesetidup vasifisok bezesecokise yicexaj
		$a_01_2 = {42 61 74 75 79 75 72 75 74 75 73 65 79 20 7a 6f 72 75 68 69 6b 65 6a 65 20 67 69 63 6f 7a 61 73 69 7a 65 68 65 20 68 65 72 61 72 69 6b 6f 6e 61 6e 6f 64 6f } //1 Batuyurutusey zoruhikeje gicozasizehe herarikonanodo
		$a_01_3 = {6c 75 79 61 6e 65 7a 69 66 20 78 6f 66 69 74 65 79 75 78 61 70 6f 76 75 68 65 73 65 6e 6f 6b 69 74 69 6c 75 70 6f 6e 65 64 65 20 79 65 6c 20 63 69 66 69 76 6f 73 69 6a 69 79 65 62 6f 6b 65 64 75 77 65 6d 75 62 65 66 6f 6e 69 } //1 luyanezif xofiteyuxapovuhesenokitiluponede yel cifivosijiyebokeduwemubefoni
		$a_01_4 = {54 69 74 75 67 61 7a 61 6d 75 77 20 64 65 73 20 6a 69 7a 69 67 61 20 6b 6f 67 75 79 69 74 61 6b 75 20 6a 6f 67 65 6b 65 78 6f 66 6f 6e 65 67 61 } //1 Titugazamuw des jiziga koguyitaku jogekexofonega
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}