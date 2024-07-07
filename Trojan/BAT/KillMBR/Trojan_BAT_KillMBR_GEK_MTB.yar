
rule Trojan_BAT_KillMBR_GEK_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.GEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 07 06 16 07 8e 69 17 59 6f 90 01 03 0a 8f 90 01 04 28 90 01 03 0a 28 90 01 03 0a 0c 00 09 17 58 0d 09 1b fe 04 13 04 11 04 2d d2 90 00 } //10
		$a_80_1 = {6d 62 72 56 69 72 75 73 20 2d 20 44 6f 20 6e 6f 74 20 72 75 6e 21 } //mbrVirus - Do not run!  1
		$a_01_2 = {54 6f 53 74 72 69 6e 67 } //1 ToString
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}