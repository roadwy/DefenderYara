
rule Trojan_BAT_Temonde_MCF_MTB{
	meta:
		description = "Trojan:BAT/Temonde.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 00 21 67 00 45 00 6c 00 30 00 59 00 4d 00 52 00 53 00 52 00 48 00 31 00 6f 00 30 00 4c 00 78 00 56 00 00 2f 50 00 6f 00 6b 00 65 00 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}