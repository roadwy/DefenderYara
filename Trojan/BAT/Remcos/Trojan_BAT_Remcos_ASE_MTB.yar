
rule Trojan_BAT_Remcos_ASE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 1a 58 4a 02 8e 69 5d 02 06 1a 58 4a 02 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 90 01 03 0a 02 06 1a 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}