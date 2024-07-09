
rule Trojan_BAT_Seraph_GPA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 05 1f 18 63 d2 6f ?? 00 00 0a 20 0b 00 00 00 38 } //2
		$a_01_1 = {11 00 11 00 1f 0c 64 61 13 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}