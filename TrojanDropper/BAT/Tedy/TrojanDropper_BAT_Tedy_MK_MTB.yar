
rule TrojanDropper_BAT_Tedy_MK_MTB{
	meta:
		description = "TrojanDropper:BAT/Tedy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 2d 09 16 8d 1f 00 00 01 0d de 24 07 08 6f 27 00 00 0a 08 6f 28 00 00 0a 0d de 14 08 2c 06 08 6f 23 00 00 0a dc } //20
		$a_01_1 = {6f 15 00 00 0a 26 06 16 06 8e 69 28 16 00 00 0a 14 0a 16 28 17 00 00 0a } //15
		$a_81_2 = {70 61 79 6c 6f 61 64 2e 65 78 65 } //5 payload.exe
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15+(#a_81_2  & 1)*5) >=40
 
}