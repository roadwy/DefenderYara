
rule Trojan_BAT_Tedy_PSTM_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 08 11 08 28 ?? 00 00 0a 11 07 6f ?? 00 00 0a 28 ?? 00 00 06 13 09 72 24 02 00 70 17 8d 13 00 00 01 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}