
rule Trojan_BAT_Disco_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Disco.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 02 18 5b 8d 90 01 01 00 00 01 13 03 38 dd ff ff ff 11 03 11 06 18 5b 11 01 11 06 18 6f 90 01 01 00 00 0a 1f 10 28 05 00 00 0a 9c 90 00 } //10
		$a_01_1 = {4f 6f 78 69 74 68 } //2 Ooxith
		$a_01_2 = {50 00 6d 00 6c 00 75 00 78 00 6a 00 6a 00 77 00 66 00 78 00 6b 00 2e 00 62 00 6d 00 70 00 } //2 Pmluxjjwfxk.bmp
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}