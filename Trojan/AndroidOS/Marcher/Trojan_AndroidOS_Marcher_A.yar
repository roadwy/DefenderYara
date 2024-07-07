
rule Trojan_AndroidOS_Marcher_A{
	meta:
		description = "Trojan:AndroidOS/Marcher.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {2d 21 70 73 21 71 62 73 66 6f 75 21 6a 65 21 31 79 } //2 -!ps!qbsfou!je!1y
		$a_01_1 = {42 64 75 6a 77 66 21 47 73 62 68 6e 66 6f 75 74 21 6a 6f 21 } //2 Bdujwf!Gsbhnfout!jo!
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}