
rule Trojan_BAT_Taskun_AACM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 08 2b 2a 08 11 05 11 07 58 11 06 11 08 58 6f ?? 00 00 0a 13 09 12 09 28 ?? 00 00 0a 13 0a 07 09 11 0a 9c 09 17 58 0d 11 08 17 58 13 08 11 08 17 32 d1 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}