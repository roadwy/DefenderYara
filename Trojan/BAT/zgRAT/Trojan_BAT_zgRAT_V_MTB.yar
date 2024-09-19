
rule Trojan_BAT_ZgRAT_V_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 00 06 d0 36 00 00 02 28 ?? 01 00 06 6f ?? 00 00 0a 73 ?? 00 00 0a 80 61 00 00 04 20 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}