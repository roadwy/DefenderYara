
rule Backdoor_BAT_AsyncRAT_PAGL_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.PAGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 17 8d 09 00 00 01 13 05 11 05 16 72 01 00 00 70 a2 11 05 0c 07 08 16 } //2
		$a_00_1 = {5b 00 30 00 32 00 34 00 35 00 37 00 38 00 39 00 37 00 34 00 61 00 73 00 66 00 36 00 38 00 34 00 33 00 73 00 72 00 36 00 67 00 38 00 37 00 67 00 36 00 37 00 5d 00 } //2 [024578974asf6843sr6g87g67]
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}