
rule TrojanSpy_AndroidOS_Svpeng_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Svpeng.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {39 00 0f 00 38 03 0d 00 12 10 5c 10 90 01 01 00 59 12 90 01 01 00 5c 14 90 01 01 00 90 00 } //1
		$a_03_1 = {02 22 05 ce 00 1a 06 02 00 70 20 90 01 02 65 00 08 00 12 00 6e 20 90 01 02 05 00 0c 05 6e 10 90 01 02 05 00 0c 05 90 00 } //1
		$a_03_2 = {08 01 24 00 6e 20 90 01 02 10 00 0c 1c 1a 1d 12 00 74 02 90 01 02 1c 00 0c 1c 08 00 1c 00 08 01 25 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}