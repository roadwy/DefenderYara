
rule Trojan_BAT_Badur_PTFI_MTB{
	meta:
		description = "Trojan:BAT/Badur.PTFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 a3 00 00 70 73 11 00 00 0a 28 90 01 01 00 00 0a 72 f7 00 00 70 28 90 01 01 00 00 0a 6f 14 00 00 0a 00 2b 01 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}