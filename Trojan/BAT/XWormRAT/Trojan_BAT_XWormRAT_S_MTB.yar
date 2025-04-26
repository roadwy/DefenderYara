
rule Trojan_BAT_XWormRAT_S_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 df b6 3f 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 3c 01 00 00 17 01 00 00 08 04 00 00 e1 0a } //2
		$a_01_1 = {43 59 51 2e 44 61 74 61 } //2 CYQ.Data
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}