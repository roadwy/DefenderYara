
rule Trojan_AndroidOS_SpyAgent_S{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.S,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 64 6f 7a 65 65 46 65 65 72 6d 69 } //2 checkdozeeFeermi
		$a_01_1 = {69 73 6e 6f 74 69 73 65 72 76 52 75 75 6e 74 74 } //2 isnotiservRuuntt
		$a_01_2 = {67 65 74 49 6e 6e 73 74 61 6c 69 6e 67 } //2 getInnstaling
		$a_01_3 = {66 61 6b 65 74 61 6b 65 53 63 72 65 65 6e 73 68 6f 74 73 73 73 73 73 73 } //2 faketakeScreenshotssssss
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}