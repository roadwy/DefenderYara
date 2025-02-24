
rule Trojan_BAT_Tedy_AMDC_MTB{
	meta:
		description = "Trojan:BAT/Tedy.AMDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 13 04 11 04 02 7e ?? 00 00 0a 7e ?? 00 00 0a 7e ?? 00 00 0a 16 20 ?? 00 00 08 7e ?? 00 00 0a 14 12 02 12 03 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}