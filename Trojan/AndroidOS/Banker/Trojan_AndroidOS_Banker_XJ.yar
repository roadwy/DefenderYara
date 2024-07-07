
rule Trojan_AndroidOS_Banker_XJ{
	meta:
		description = "Trojan:AndroidOS/Banker.XJ,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d8 04 04 52 48 07 03 08 14 09 50 2e 97 00 91 01 09 01 dc 09 08 03 48 09 06 09 da 0b 04 50 91 0b 01 0b da 04 04 00 b3 b4 b0 04 b0 74 93 07 01 01 b1 a7 b0 74 94 07 01 01 b0 74 b7 94 8d 44 4f 04 05 08 13 04 24 00 b3 b4 b0 14 d8 07 04 a8 d8 08 08 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}