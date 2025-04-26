
rule Trojan_AndroidOS_Banker_J_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {b0 82 94 08 00 00 91 09 05 02 b0 09 da 09 09 00 b0 97 b3 00 db 00 00 01 df 00 00 01 b0 70 b0 80 b7 30 8d 00 8d 00 8d 00 4f 00 06 04 d8 03 04 01 14 00 ec 64 01 00 92 04 05 02 14 07 38 02 01 00 b0 74 b0 40 01 34 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}