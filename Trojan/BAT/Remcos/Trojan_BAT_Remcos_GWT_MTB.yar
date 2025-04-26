
rule Trojan_BAT_Remcos_GWT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GWT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 8f 0d 00 00 01 25 71 0d 00 00 01 06 07 1f 10 5d 91 61 d2 81 0d 00 00 01 07 17 58 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}