
rule Trojan_BAT_LokiBot_ER_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2e 65 64 6f 6d 20 53 4f 44 20 6e 69 20 6e 75 72 20 65 62 20 74 6f 6e 6e 61 63 20 6d 61 72 67 6f 72 70 20 73 69 68 54 21 } //1 .edom SOD ni nur eb tonnac margorp sihT!
		$a_01_1 = {6c 6c 64 2e 65 65 72 6f 63 73 6d } //1 lld.eerocsm
		$a_01_2 = {6e 69 61 4d 6c 6c 44 72 6f 43 5f } //1 niaMllDroC_
		$a_01_3 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_01_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_5 = {4d 6f 7a 69 6c 6c 61 } //1 Mozilla
		$a_01_6 = {53 00 6c 00 65 00 65 00 70 00 } //1 Sleep
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}