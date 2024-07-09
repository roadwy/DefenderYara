
rule TrojanDropper_AndroidOS_Hqwar_D_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Hqwar.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d2 00 99 0b [0-04] b0 30 [0-04] 54 d3 [0-07] 21 33 [0-04] 54 d4 [0-07] 21 44 [0-04] b1 43 [0-04] b0 30 [0-04] 52 d3 [0-07] d0 33 5d 09 [0-04] d0 33 12 05 [0-04] d8 03 03 48 [0-04] 52 d4 [0-07] b0 43 [0-04] b0 30 [0-04] 59 d0 [0-07] 54 d0 [0-07] 21 00 [0-04] d1 00 0f 3f } //1
		$a_01_1 = {73 65 43 2f 64 75 65 78 72 79 2f 73 75 6c 50 69 79 6d } //1 seC/duexry/sulPiym
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}