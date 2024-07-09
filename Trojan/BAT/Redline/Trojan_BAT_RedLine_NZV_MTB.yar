
rule Trojan_BAT_RedLine_NZV_MTB{
	meta:
		description = "Trojan:BAT/RedLine.NZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f 00 08 20 00 04 00 00 58 28 ?? 00 00 2b 07 02 08 20 00 04 00 00 6f ?? 00 00 0a 0d 08 09 58 0c 09 20 00 04 00 00 2f } //1
		$a_81_1 = {67 68 67 62 65 76 6e 79 2e 74 6c 6e } //1 ghgbevny.tln
		$a_81_2 = {72 7a 63 67 6c } //1 rzcgl
		$a_81_3 = {57 57 51 57 51 57 } //1 WWQWQW
		$a_81_4 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}