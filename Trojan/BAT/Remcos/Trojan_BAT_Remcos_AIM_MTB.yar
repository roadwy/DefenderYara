
rule Trojan_BAT_Remcos_AIM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 30 07 0d 16 13 04 09 12 04 28 90 01 03 0a 06 08 28 90 01 03 06 13 05 07 08 11 05 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}