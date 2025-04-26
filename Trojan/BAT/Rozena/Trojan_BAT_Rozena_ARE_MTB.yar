
rule Trojan_BAT_Rozena_ARE_MTB{
	meta:
		description = "Trojan:BAT/Rozena.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 06 16 07 06 8e 69 28 ?? 00 00 0a 00 7e ?? 00 00 0a 0c 7e ?? 00 00 0a 7e ?? 00 00 0a 07 7e ?? 00 00 0a 16 12 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}