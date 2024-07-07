
rule Trojan_BAT_EternityStealer_AE_MTB{
	meta:
		description = "Trojan:BAT/EternityStealer.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 26 16 0c 2b 12 06 6f 90 01 01 00 00 0a 07 08 9a 6f 90 01 01 00 00 0a 08 17 d6 0c 08 07 8e 69 32 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}