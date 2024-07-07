
rule Trojan_BAT_Seraph_AATZ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AATZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 13 06 20 08 00 00 00 38 90 01 01 ff ff ff 11 03 11 01 6f 90 01 01 00 00 0a 3f 90 01 01 00 00 00 20 05 00 00 00 38 90 01 01 ff ff ff 11 01 11 03 16 28 90 01 01 00 00 06 13 04 20 02 00 00 00 7e 90 01 01 09 00 04 7b 90 01 01 09 00 04 39 90 01 01 ff ff ff 26 20 02 00 00 00 38 90 01 01 ff ff ff 11 08 11 0a 6f 90 01 01 00 00 0a 20 05 00 00 00 7e 90 00 } //4
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}