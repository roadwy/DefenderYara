
rule Trojan_BAT_Redcap_PTCO_MTB{
	meta:
		description = "Trojan:BAT/Redcap.PTCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 6f 66 00 00 0a 0d 09 28 90 01 01 00 00 0a 0c 28 90 01 01 00 00 06 6f 68 00 00 0a 6f 69 00 00 0a 72 83 02 00 70 28 90 01 01 00 00 0a 0b 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}