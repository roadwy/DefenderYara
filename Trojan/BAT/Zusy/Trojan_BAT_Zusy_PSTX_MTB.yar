
rule Trojan_BAT_Zusy_PSTX_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSTX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 13 00 00 0a 25 6f ?? 00 00 0a 72 01 00 00 70 72 1b 00 00 70 6f ?? 00 00 0a 02 0a 03 28 ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 26 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}