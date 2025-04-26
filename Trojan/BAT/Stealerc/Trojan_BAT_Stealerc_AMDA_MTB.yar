
rule Trojan_BAT_Stealerc_AMDA_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.AMDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 02 16 02 8e 69 6f ?? 00 00 0a 13 03 20 } //4
		$a_03_1 = {0a 26 20 00 00 00 00 7e ?? ?? 00 04 7b 90 0a 40 00 d0 ?? 00 00 01 28 ?? 00 00 0a 11 ?? 6f ?? 00 00 0a 11 ?? a3 ?? 00 00 01 72 ?? 00 00 70 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}