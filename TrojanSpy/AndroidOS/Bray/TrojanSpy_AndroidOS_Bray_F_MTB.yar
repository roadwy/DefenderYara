
rule TrojanSpy_AndroidOS_Bray_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Bray.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_00_0 = {22 01 70 00 70 10 33 02 01 00 6e 10 2d 02 05 00 0c 02 12 00 21 23 35 30 33 00 dc 03 00 04 2b 03 35 00 00 00 49 03 02 00 df 03 03 ff 8e 33 6e 20 34 02 31 00 d8 00 00 01 28 ee 49 03 02 00 14 04 4f db 04 00 b7 43 8e 33 6e 20 34 02 31 00 28 f3 49 03 02 00 14 04 d7 de d3 59 b7 43 8e 33 6e 20 34 02 31 00 28 e8 49 03 02 00 14 04 0d 09 d6 a0 b7 43 8e 33 6e 20 34 02 31 00 28 dd 6e 10 39 02 01 00 0c 00 11 00 } //2
	condition:
		((#a_00_0  & 1)*2) >=2
 
}