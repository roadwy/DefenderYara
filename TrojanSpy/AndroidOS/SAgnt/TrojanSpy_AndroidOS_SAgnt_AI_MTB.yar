
rule TrojanSpy_AndroidOS_SAgnt_AI_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AI!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 40 87 07 28 1e 54 67 b4 17 54 70 f0 16 54 00 b7 17 52 00 99 17 82 00 6e 10 4c 36 07 00 0a 07 c8 70 } //1
		$a_01_1 = {d8 03 01 ff 6e 20 05 32 18 00 0a 04 62 05 9a 15 46 06 05 09 12 07 49 06 06 07 b7 64 8e 44 50 04 00 01 3b 03 03 00 28 10 d8 01 01 fe 6e 20 05 32 38 00 0a 04 46 05 05 09 49 05 05 02 b7 54 8e 44 50 04 00 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}