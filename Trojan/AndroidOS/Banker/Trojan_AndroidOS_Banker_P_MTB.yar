
rule Trojan_AndroidOS_Banker_P_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {35 04 2a 00 48 07 02 04 d0 68 d7 dd dc 09 04 02 48 09 01 09 14 0a a5 6f 0a 00 91 0b 08 06 b1 ab 92 0a 08 06 b0 ab da 0b 0b 00 b0 7b b3 88 db 08 08 01 df 07 08 01 b0 7b 94 07 06 06 b0 7b 97 07 0b 09 8d 77 4f 07 05 04 13 07 26 05 b3 67 d8 04 04 01 28 d7 } //00 00 
	condition:
		any of ($a_*)
 
}