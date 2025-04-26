
rule Trojan_AndroidOS_Banker_L_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d1 11 11 24 48 04 02 07 d0 33 d0 1a dc 08 07 02 48 08 06 08 14 0a 99 90 00 00 93 0b 01 03 b0 ba 91 0b 03 0a b0 1b da 0b 0b 00 b0 4b 93 04 01 01 db 04 04 01 df 04 04 01 b0 4b b4 11 b0 1b 97 01 0b 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}