
rule TrojanSpy_AndroidOS_Fakecalls_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecalls.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 10 b9 01 02 00 0c 00 38 00 20 00 54 20 69 01 39 00 19 00 6e 10 be 01 02 00 0c 00 1f 00 d0 01 38 00 06 00 54 00 66 01 5b 20 69 01 54 20 69 01 39 00 09 00 22 00 9f 03 70 10 c2 1d 00 00 5b 20 69 01 54 20 69 01 } //1
		$a_01_1 = {70 10 85 19 04 00 22 00 92 03 70 20 87 1d 40 00 5b 40 67 01 71 10 39 23 04 00 0c 00 5b 40 68 01 22 00 d5 01 22 01 cf 01 70 20 45 0d 41 00 70 20 5c 0d 10 00 5b 40 6a 01 6e 10 49 0d 04 00 0c 00 38 00 33 00 60 00 ff 00 13 01 13 00 34 10 0e 00 6e 10 49 0d 04 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}