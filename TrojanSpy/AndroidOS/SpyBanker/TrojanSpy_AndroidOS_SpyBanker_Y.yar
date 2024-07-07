
rule TrojanSpy_AndroidOS_SpyBanker_Y{
	meta:
		description = "TrojanSpy:AndroidOS/SpyBanker.Y,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 54 55 53 45 52 4e 41 4d 45 } //1 ETUSERNAME
		$a_01_1 = {45 6d 61 69 6c 20 49 64 20 69 73 20 72 65 71 75 69 72 65 64 21 } //2 Email Id is required!
		$a_01_2 = {63 6f 6d 2e 73 6b 2e 61 78 69 73 62 61 6e 6b } //2 com.sk.axisbank
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 61 78 69 73 62 61 6e 6b 73 74 6f 72 65 2e 63 6f } //1 https://axisbankstore.co
		$a_01_4 = {68 74 74 70 73 3a 2f 2f 61 78 69 73 65 64 67 65 73 74 6f 72 65 2e 63 6f 6d 2f } //1 https://axisedgestore.com/
		$a_01_5 = {68 74 74 70 73 3a 2f 2f 61 78 69 73 62 61 6e 6b 70 6f 69 6e 74 73 2e 63 6f 6d } //1 https://axisbankpoints.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}