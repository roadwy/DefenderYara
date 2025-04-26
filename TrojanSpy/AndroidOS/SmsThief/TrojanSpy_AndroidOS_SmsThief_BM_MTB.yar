
rule TrojanSpy_AndroidOS_SmsThief_BM_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.BM!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 10 00 0c 00 54 21 1a 00 71 10 ?? 00 01 00 0c 01 6e 20 ?? 00 10 00 0c 00 6e 10 ?? 00 00 00 0c 00 5b 20 1c 00 } //1
		$a_01_1 = {22 00 08 00 54 31 03 00 6e 10 40 00 01 00 0c 01 1c 02 30 00 70 30 08 00 10 02 54 31 03 00 6e 20 4c 00 01 00 54 31 03 00 6e 10 3f 00 01 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}