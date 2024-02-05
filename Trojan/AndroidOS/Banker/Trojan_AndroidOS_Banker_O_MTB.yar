
rule Trojan_AndroidOS_Banker_O_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {35 06 2a 00 48 07 02 06 d0 48 d7 dd dc 0a 06 03 48 0a 01 0a 14 0b a5 6f 0a 00 91 0c 08 04 b1 bc 92 0b 08 04 b0 bc da 0c 0c 00 b0 7c b3 88 db 08 08 01 df 07 08 01 b0 7c 94 07 04 04 b0 7c 97 07 0c 0a 8d 77 4f 07 05 06 13 07 26 05 b3 47 d8 06 06 01 28 d7 } //00 00 
	condition:
		any of ($a_*)
 
}