
rule Trojan_BAT_Hanoone_RS_MTB{
	meta:
		description = "Trojan:BAT/Hanoone.RS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 06 07 28 0d 00 00 06 25 26 0b 1b 17 2d 08 26 14 0b 2b 20 16 0c 08 45 06 00 00 00 8c ff ff ff dc ff ff ff 00 00 00 00 dc ff ff ff cc ff ff ff 06 00 00 00 2b ca } //1
		$a_01_1 = {51 00 55 00 31 00 45 00 49 00 46 00 42 00 79 00 62 00 32 00 4e 00 6c 00 63 00 33 00 4e 00 76 00 63 00 69 00 51 00 } //1 QU1EIFByb2Nlc3NvciQ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}