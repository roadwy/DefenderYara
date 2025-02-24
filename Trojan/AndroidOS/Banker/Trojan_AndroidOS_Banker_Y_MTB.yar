
rule Trojan_AndroidOS_Banker_Y_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.Y!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {71 10 33 00 00 00 0c 00 54 64 1e 00 71 10 34 00 04 00 0c 04 52 65 1b 00 71 10 9a 2b 05 00 0c 05 72 30 5b 37 40 05 0c 00 1f 00 21 08 39 00 14 00 22 00 fe 09 52 61 1a 00 54 64 1e 00 71 10 34 00 04 00 0c 04 71 10 80 00 04 00 0a 04 70 30 fe 37 10 04 } //1
		$a_01_1 = {77 01 68 00 17 00 0a 00 df 00 00 01 38 00 c2 00 77 01 8e 00 15 00 0c 00 74 01 f3 2b 15 00 0a 01 74 01 f3 2b 16 00 0a 03 72 10 66 2d 00 00 0a 04 b2 43 90 08 01 03 77 01 5f 00 16 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}