
rule TrojanDropper_AndroidOS_Hqwar_D_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Hqwar.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d2 00 99 0b 90 02 04 b0 30 90 02 04 54 d3 90 02 07 21 33 90 02 04 54 d4 90 02 07 21 44 90 02 04 b1 43 90 02 04 b0 30 90 02 04 52 d3 90 02 07 d0 33 5d 09 90 02 04 d0 33 12 05 90 02 04 d8 03 03 48 90 02 04 52 d4 90 02 07 b0 43 90 02 04 b0 30 90 02 04 59 d0 90 02 07 54 d0 90 02 07 21 00 90 02 04 d1 00 0f 3f 90 00 } //1
		$a_01_1 = {73 65 43 2f 64 75 65 78 72 79 2f 73 75 6c 50 69 79 6d } //1 seC/duexry/sulPiym
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}