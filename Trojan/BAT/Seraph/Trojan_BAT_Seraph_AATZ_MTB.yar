
rule Trojan_BAT_Seraph_AATZ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AATZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 13 06 20 08 00 00 00 38 ?? ff ff ff 11 03 11 01 6f ?? 00 00 0a 3f ?? 00 00 00 20 05 00 00 00 38 ?? ff ff ff 11 01 11 03 16 28 ?? 00 00 06 13 04 20 02 00 00 00 7e ?? 09 00 04 7b ?? 09 00 04 39 ?? ff ff ff 26 20 02 00 00 00 38 ?? ff ff ff 11 08 11 0a 6f ?? 00 00 0a 20 05 00 00 00 7e } //4
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}