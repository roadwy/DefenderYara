
rule Trojan_BAT_Convagent_ACV_MTB{
	meta:
		description = "Trojan:BAT/Convagent.ACV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0a 16 0b 2b 13 00 07 0a 07 1b fe 01 0c 08 2c 03 00 2b 0e 00 07 17 58 0b 07 1f 0a fe 04 0d 09 2d e4 } //2
		$a_01_1 = {76 69 73 75 6c 61 20 73 74 75 64 69 6f 5c 62 75 63 6c 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 62 75 63 6c 65 2e 70 64 62 } //1 visula studio\bucle\obj\Debug\bucle.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}