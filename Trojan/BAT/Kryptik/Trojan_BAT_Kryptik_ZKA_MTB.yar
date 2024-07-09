
rule Trojan_BAT_Kryptik_ZKA_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.ZKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 43 00 00 70 28 ?? ?? ?? 06 0a 72 85 00 00 70 28 ?? ?? ?? 06 0b 06 72 c7 00 00 70 72 09 01 00 70 28 ?? ?? ?? 06 0a 07 72 c7 00 00 70 72 09 01 00 70 28 ?? ?? ?? 06 0b 06 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}