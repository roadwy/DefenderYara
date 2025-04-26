
rule TrojanSpy_AndroidOS_SmsSpy_S_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsSpy.S!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 6b 75 6e 67 65 2f 7a 68 69 74 6f 6e 67 63 61 72 } //1 com/kunge/zhitongcar
		$a_03_1 = {0b 10 00 6e 20 ?? 0b 10 00 6e 20 ?? 0b 10 00 6e 20 ?? 0b 10 00 22 00 ff 0f 70 10 ?? 5d 00 00 6e 20 ?? 0b 04 00 1a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}