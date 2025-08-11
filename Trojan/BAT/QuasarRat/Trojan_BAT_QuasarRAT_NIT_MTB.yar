
rule Trojan_BAT_QuasarRAT_NIT_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {38 27 00 00 00 28 ?? 00 00 0a 72 01 00 00 70 28 ?? 00 00 0a 25 11 01 28 ?? 00 00 0a 28 ?? 00 00 0a 26 20 02 00 00 00 38 bb ff ff ff 38 66 00 00 00 20 04 00 00 00 fe 0e 03 00 38 a4 ff ff ff 11 04 72 0b 00 00 70 6f 08 00 00 0a 6f 09 00 00 0a 13 01 20 00 00 00 00 7e 0b 00 00 04 7b 30 00 00 04 3a 81 ff ff ff 26 20 01 00 00 00 38 76 ff ff ff 11 01 3a 8d ff ff ff 20 00 00 00 00 7e 0b 00 00 04 7b 48 00 00 04 3a 5b ff ff ff 26 20 00 00 00 00 38 50 ff ff ff } //2
		$a_01_1 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //2 WriteAllBytes
		$a_01_2 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //2 GetByteArrayAsync
		$a_01_3 = {46 72 6f 6d 4d 69 6e 75 74 65 73 } //1 FromMinutes
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}