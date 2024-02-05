
rule Trojan_AndroidOS_Banker_Q_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.Q!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {35 07 2a 00 48 08 02 07 d0 39 d7 dd dc 0a 07 01 48 0a 01 0a 14 0b a5 6f 0a 00 91 0c 09 03 b1 bc 92 0b 09 03 b0 bc da 0c 0c 00 b0 8c b3 99 db 09 09 01 df 08 09 01 b0 8c 94 08 03 03 b0 8c 97 08 0c 0a 8d 88 4f 08 05 07 13 08 26 05 b3 38 d8 07 07 01 28 d7 } //00 00 
	condition:
		any of ($a_*)
 
}