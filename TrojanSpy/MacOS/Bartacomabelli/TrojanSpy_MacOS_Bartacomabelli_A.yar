
rule TrojanSpy_MacOS_Bartacomabelli_A{
	meta:
		description = "TrojanSpy:MacOS/Bartacomabelli.A,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 0b 80 f1 aa 88 08 48 ff c3 48 ff c0 49 ff ce 75 ee } //1
		$a_03_1 = {c6 de d8 c5 99 cc d2 d9 90 02 10 d9 d3 9d d2 d9 db cd d0 90 02 18 84 c5 c4 c3 90 02 10 c5 c4 90 00 } //2
		$a_03_2 = {85 ff d9 cf d8 d9 85 f9 90 02 10 c2 cb d8 cf 90 02 10 ce 85 90 00 } //2
		$a_03_3 = {e9 c5 c4 de cf c4 de d9 90 02 10 85 e7 cb c9 e5 f9 85 eb 90 02 10 da da f9 de c5 d8 cf aa 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=3
 
}