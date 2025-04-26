
rule Trojan_BAT_Gozi_MA_MTB{
	meta:
		description = "Trojan:BAT/Gozi.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 9f a2 2b 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 da 00 00 00 01 01 00 00 e2 04 } //2
		$a_01_1 = {33 61 32 63 37 38 37 66 2d 36 37 63 62 2d 34 30 63 32 2d 38 39 66 34 2d 61 61 35 65 65 30 64 33 63 33 63 63 } //2 3a2c787f-67cb-40c2-89f4-aa5ee0d3c3cc
		$a_01_2 = {59 74 74 73 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 Yttsm.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}