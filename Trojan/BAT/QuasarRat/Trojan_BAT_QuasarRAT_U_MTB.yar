
rule Trojan_BAT_QuasarRAT_U_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 9f a2 29 09 03 00 00 00 fe 01 33 00 00 00 00 01 00 00 00 44 00 00 00 30 00 00 00 32 01 00 00 24 01 } //2
		$a_01_1 = {2d 00 6e 00 65 00 74 00 7a 00 2e 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 -netz.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}