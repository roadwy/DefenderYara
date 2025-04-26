
rule Trojan_BAT_Loki_B_MTB{
	meta:
		description = "Trojan:BAT/Loki.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 01 02 8e 69 5d 02 11 01 02 8e 69 5d 91 11 00 11 01 11 00 8e 69 5d 91 61 28 ?? ?? ?? 06 02 11 01 17 58 02 8e 69 5d 91 28 ?? ?? ?? 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}