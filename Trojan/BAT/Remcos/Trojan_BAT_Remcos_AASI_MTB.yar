
rule Trojan_BAT_Remcos_AASI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 8d ?? 00 00 01 0c 16 0d 38 ?? 00 00 00 08 09 07 09 91 06 59 d2 9c 09 17 58 0d 09 07 8e 69 32 ed } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}