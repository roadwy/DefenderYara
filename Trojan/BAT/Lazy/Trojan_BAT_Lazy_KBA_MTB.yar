
rule Trojan_BAT_Lazy_KBA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.KBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 15 11 16 9a 13 0b 11 09 11 0b 6f 90 01 01 00 00 0a 11 16 17 58 13 16 11 16 11 15 28 90 01 01 00 00 06 69 32 de 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}