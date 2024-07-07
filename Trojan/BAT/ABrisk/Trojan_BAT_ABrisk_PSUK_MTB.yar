
rule Trojan_BAT_ABrisk_PSUK_MTB{
	meta:
		description = "Trojan:BAT/ABrisk.PSUK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 02 16 02 8e 69 6f 90 01 01 00 00 0a 09 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 13 04 de 0d 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}