
rule Trojan_BAT_Redline_NEF_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 72 59 00 00 70 72 ?? 00 00 70 28 ?? 00 00 0a 26 2a } //1
		$a_01_1 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_01_2 = {45 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 2e 00 74 00 78 00 74 00 } //1 Encoding.txt
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}