
rule TrojanSpy_BAT_Stealer_PQ_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 6a 00 6b 00 67 00 68 00 68 00 6a 00 66 00 2e 00 6a 00 70 00 67 00 } //7 resources/jkghhjf.jpg
		$a_80_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
		$a_80_2 = {47 5a 69 70 53 74 72 65 61 6d } //GZipStream  1
	condition:
		((#a_00_0  & 1)*7+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=9
 
}