
rule Trojan_AndroidOS_Banker_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {35 02 35 00 d1 11 11 24 48 06 03 02 d0 44 d0 1a dc 09 02 03 48 09 08 09 14 0a 99 90 00 00 93 0b 01 04 b0 ba 91 0b 04 0a b0 1b da 0b 0b 00 b0 6b 93 06 01 01 db 06 06 01 df 06 06 01 b0 6b b4 11 b0 1b 97 01 0b 09 8d 11 4f 01 05 02 } //00 00 
	condition:
		any of ($a_*)
 
}