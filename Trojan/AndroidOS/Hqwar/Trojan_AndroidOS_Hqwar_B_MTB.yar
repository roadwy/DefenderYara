
rule Trojan_AndroidOS_Hqwar_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Hqwar.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 04 61 57 04 00 b1 48 48 04 00 06 14 05 31 22 0b 00 92 05 05 08 dc 07 06 01 48 07 03 07 14 09 [0-02] 0e 00 92 08 08 09 da 09 05 37 b0 98 b7 74 8d 44 4f 04 01 06 b0 85 d8 09 05 fe d8 06 06 01 } //1
		$a_03_1 = {48 09 07 09 14 0a 27 40 08 00 b1 2a b0 23 b1 a3 b0 63 b7 98 8d 88 4f 08 05 00 14 08 f5 d0 01 00 32 83 [0-02] b0 23 81 28 81 3a be a8 14 08 eb e8 01 00 ?? 09 06 03 b1 29 b0 89 01 92 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}