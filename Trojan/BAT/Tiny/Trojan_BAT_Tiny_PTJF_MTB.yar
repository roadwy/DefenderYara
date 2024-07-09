
rule Trojan_BAT_Tiny_PTJF_MTB{
	meta:
		description = "Trojan:BAT/Tiny.PTJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 0f 00 00 0a 02 03 28 ?? 00 00 0a 00 03 1c 28 ?? 00 00 0a 00 03 17 8d 16 00 00 01 25 16 1f 5c 9d 6f 14 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}