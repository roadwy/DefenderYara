
rule Trojan_BAT_Redline_GNW_MTB{
	meta:
		description = "Trojan:BAT/Redline.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {49 51 4a 4f 44 44 73 70 49 6e 38 3d } //IQJODDspIn8=  1
		$a_80_1 = {44 42 55 55 44 43 34 36 49 6a 63 69 49 7a 42 52 49 67 30 58 58 6a 67 54 4a 46 73 71 42 67 77 50 } //DBUUDC46IjciIzBRIg0XXjgTJFsqBgwP  1
		$a_01_2 = {75 37 78 71 6d 72 4d } //1 u7xqmrM
		$a_01_3 = {5a 50 45 4b 6a 42 } //1 ZPEKjB
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}