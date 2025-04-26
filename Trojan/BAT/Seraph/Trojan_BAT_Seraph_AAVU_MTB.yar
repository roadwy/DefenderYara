
rule Trojan_BAT_Seraph_AAVU_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAVU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 08 11 05 6f ?? 00 00 0a 20 07 00 00 00 38 ?? ff ff ff 38 ?? ff ff ff 20 03 00 00 00 38 ?? ff ff ff 11 01 11 09 16 28 ?? 00 00 06 13 0b 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? fe ff ff 26 } //4
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}