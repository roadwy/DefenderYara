
rule Trojan_BAT_Remcos_SLA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SLA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 11 00 00 06 0a 72 41 01 00 70 0b 73 56 00 00 0a 25 72 c6 01 00 70 6f 57 00 00 0a 00 25 72 08 02 00 70 6f 58 00 00 0a 00 0c 07 08 28 59 00 00 0a 6f 5a 00 00 0a 0d 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}