
rule Trojan_BAT_RedLine_RDEZ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 05 08 5d 08 58 08 5d 91 11 06 61 11 08 59 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}