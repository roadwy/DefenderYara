
rule TrojanSpy_AndroidOS_SoumniBot_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SoumniBot.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 00 22 00 ?? 11 70 10 ?? ?? 00 00 62 01 ?? 4b 6e 10 ?? ?? 01 00 0c 02 6e 10 ?? ?? 01 00 0c 01 6e 30 ?? ?? 20 01 0c 00 22 01 ?? ?? 70 10 ?? ?? 01 00 6e 20 ?? ?? 10 00 } //1
		$a_03_1 = {08 00 1a 00 ?? ?? 71 20 ?? ?? 08 00 0a 00 39 00 b3 00 1a 00 ?? 5d 71 10 ?? ?? 00 00 0c 02 6e 10 ?? ?? 08 00 0c 01 12 03 12 04 12 05 12 06 74 06 ?? ?? 01 00 0c 00 38 00 9f 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}