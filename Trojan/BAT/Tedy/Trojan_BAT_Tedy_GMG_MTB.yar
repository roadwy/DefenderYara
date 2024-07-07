
rule Trojan_BAT_Tedy_GMG_MTB{
	meta:
		description = "Trojan:BAT/Tedy.GMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 9a 14 17 8d 0f 00 00 01 25 16 02 a2 6f 90 01 03 0a 26 2a 90 00 } //10
		$a_80_1 = {45 71 67 67 70 73 63 65 2e 65 78 65 } //Eqggpsce.exe  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}