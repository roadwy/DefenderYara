
rule Trojan_AndroidOS_Banker_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {35 12 32 00 d1 95 11 24 d0 09 d0 1a 14 00 99 90 00 00 93 08 05 09 b0 80 91 08 09 00 b0 58 da 08 08 00 48 0a 03 02 b0 a8 93 0a 05 05 db 0a 0a 01 df 0a 0a 01 b0 a8 b4 55 b0 58 dc 05 02 02 48 05 07 05 b7 85 8d 55 4f 05 04 02 14 05 ec 64 01 00 92 08 09 00 b0 58 14 05 38 02 01 00 b0 85 d8 02 02 01 } //00 00 
	condition:
		any of ($a_*)
 
}