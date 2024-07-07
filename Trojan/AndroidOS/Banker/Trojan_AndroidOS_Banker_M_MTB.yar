
rule Trojan_AndroidOS_Banker_M_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {35 07 2a 00 48 08 03 07 d0 59 d7 dd dc 0a 07 03 48 0a 01 0a 14 0b a5 6f 0a 00 91 0c 09 05 b1 bc 92 0b 09 05 b0 bc da 0c 0c 00 b0 8c b3 99 db 09 09 01 df 08 09 01 b0 8c 94 08 05 05 b0 8c 97 08 0c 0a 8d 88 4f 08 06 07 13 08 26 05 b3 58 d8 07 07 01 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}