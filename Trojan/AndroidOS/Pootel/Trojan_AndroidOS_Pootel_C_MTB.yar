
rule Trojan_AndroidOS_Pootel_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Pootel.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 01 ee 0d 1d 00 0a 04 b5 84 33 84 0f 00 6e 20 e9 0d 91 00 0a 0a 74 01 99 0e 1c 00 0a 04 db 0b 04 02 13 04 1a 00 28 04 12 04 12 0a 12 0b } //1
		$a_01_1 = {22 00 ce 01 70 10 1c 11 00 00 6e 20 1b 11 03 00 22 00 6b 03 70 10 0a 11 00 00 6e 20 19 11 03 00 6e 20 46 0f 23 00 71 10 1a 11 01 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}