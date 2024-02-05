
rule Trojan_AndroidOS_Banker_N_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {35 06 2a 00 48 07 03 06 d0 28 d7 dd dc 09 06 02 48 09 01 09 14 0a a5 6f 0a 00 91 0b 08 02 b1 ab 92 0a 08 02 b0 ab da 0b 0b 00 b0 7b b3 88 db 08 08 01 df 07 08 01 b0 7b 94 07 02 02 b0 7b 97 07 0b 09 8d 77 4f 07 05 06 13 07 26 05 b3 27 d8 06 06 01 28 d7 } //00 00 
	condition:
		any of ($a_*)
 
}