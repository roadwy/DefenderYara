
rule Trojan_BAT_Bobik_PSTQ_MTB{
	meta:
		description = "Trojan:BAT/Bobik.PSTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 19 00 00 0a 0a 06 28 ?? 00 00 0a 0b 07 16 16 16 16 06 6f ?? 00 00 0a 6f ?? 00 00 0a 00 06 72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 72 01 00 00 70 28 ?? 00 00 0a 13 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}