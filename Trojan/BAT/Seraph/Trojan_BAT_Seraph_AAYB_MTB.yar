
rule Trojan_BAT_Seraph_AAYB_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 07 11 01 94 11 07 11 03 94 58 20 00 01 00 00 5d 94 13 04 } //2
		$a_01_1 = {11 08 11 02 11 09 11 02 91 11 04 61 d2 9c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}