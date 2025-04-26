
rule Trojan_BAT_Nekark_MBDA_MTB{
	meta:
		description = "Trojan:BAT/Nekark.MBDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 cf 17 00 70 6f ?? 00 00 0a 74 ?? 00 00 01 72 db 17 00 70 72 df 17 00 70 6f ?? 00 00 0a 72 e5 17 00 70 72 e9 17 00 70 6f ?? 00 00 0a 17 8d ?? 00 00 01 25 16 1f 24 9d 6f ce 00 00 0a 0b 07 8e 69 8d ?? 00 00 01 0c 16 13 04 2b 17 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}