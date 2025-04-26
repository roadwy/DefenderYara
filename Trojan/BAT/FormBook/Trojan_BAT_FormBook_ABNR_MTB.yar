
rule Trojan_BAT_FormBook_ABNR_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04 02 } //5
		$a_01_1 = {48 00 34 00 46 00 5a 00 54 00 47 00 43 00 58 00 38 00 37 00 58 00 34 00 38 00 42 00 46 00 37 00 34 00 47 00 42 00 35 00 38 00 38 00 } //1 H4FZTGCX87X48BF74GB588
		$a_01_2 = {4b 00 72 00 75 00 73 00 6b 00 61 00 6c 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Kruskal.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}