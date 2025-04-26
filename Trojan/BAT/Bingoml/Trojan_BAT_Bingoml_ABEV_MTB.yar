
rule Trojan_BAT_Bingoml_ABEV_MTB{
	meta:
		description = "Trojan:BAT/Bingoml.ABEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {1f 1a 28 13 00 00 0a 72 01 00 00 70 28 14 00 00 0a 25 28 03 00 00 06 28 15 00 00 0a 28 16 00 00 0a 26 73 17 00 00 0a 0a } //2
		$a_01_1 = {5c 00 72 00 65 00 61 00 64 00 6d 00 65 00 72 00 63 00 73 00 2e 00 74 00 78 00 74 00 } //1 \readmercs.txt
		$a_01_2 = {44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Document.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}