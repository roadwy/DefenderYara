
rule Trojan_BAT_Barys_NB_MTB{
	meta:
		description = "Trojan:BAT/Barys.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 2e 00 00 0a 0c 72 6d 01 00 70 72 fb 00 00 70 28 2f 00 00 0a 28 30 00 00 0a 74 14 00 00 01 0d 09 72 29 01 00 70 6f 31 00 00 0a 09 72 33 01 00 70 6f 32 00 00 0a 09 20 10 27 00 00 6f 33 00 00 0a 09 20 10 27 00 00 6f 34 00 00 0a 09 16 6f 35 00 00 0a 28 36 00 00 0a 08 6f 37 00 00 0a } //2
		$a_01_1 = {11 06 6f 3d 00 00 0a 73 3e 00 00 0a 6f 3f 00 00 0a 13 07 11 06 6f 40 00 00 0a 20 c8 00 00 00 2e 05 dd 83 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}