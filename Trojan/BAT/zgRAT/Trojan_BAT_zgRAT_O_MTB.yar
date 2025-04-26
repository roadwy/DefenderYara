
rule Trojan_BAT_ZgRAT_O_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 00 06 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 26 20 } //2
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_2 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}