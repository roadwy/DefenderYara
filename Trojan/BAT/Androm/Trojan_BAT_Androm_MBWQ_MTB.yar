
rule Trojan_BAT_Androm_MBWQ_MTB{
	meta:
		description = "Trojan:BAT/Androm.MBWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {05 63 00 72 00 00 05 72 00 72 00 00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}