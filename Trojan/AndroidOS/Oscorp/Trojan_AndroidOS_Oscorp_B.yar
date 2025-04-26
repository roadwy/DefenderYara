
rule Trojan_AndroidOS_Oscorp_B{
	meta:
		description = "Trojan:AndroidOS/Oscorp.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 61 70 77 71 70 64 6f 78 32 30 31 71 2f 78 6c 30 35 36 32 30 31 33 7a 70 65 65 74 79 70 77 71 71 2f 4d 6d 73 52 65 } //1 mapwqpdox201q/xl0562013zpeetypwqq/MmsRe
		$a_00_1 = {2f 6f 65 65 71 30 34 35 37 35 30 32 77 70 73 39 35 31 2f 4c 75 6b 61 73 } //1 /oeeq0457502wps951/Lukas
		$a_00_2 = {53 74 69 6c 6c 20 64 65 63 6f 6d 70 69 6c 69 6e 67 20 2c 20 6d 79 20 6e 69 67 67 61 3f } //1 Still decompiling , my nigga?
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}