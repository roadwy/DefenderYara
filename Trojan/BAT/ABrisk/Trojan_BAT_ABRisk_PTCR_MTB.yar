
rule Trojan_BAT_ABRisk_PTCR_MTB{
	meta:
		description = "Trojan:BAT/ABRisk.PTCR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 21 00 00 70 0a 28 ?? 00 00 0a 0b 00 73 43 00 00 0a 0d 09 06 6f 44 00 00 0a 6f 45 00 00 0a 0c de 0c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}