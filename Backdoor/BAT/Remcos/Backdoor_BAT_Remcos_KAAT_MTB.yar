
rule Backdoor_BAT_Remcos_KAAT_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.KAAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 02 17 59 6f ?? 00 00 0a 07 8e 69 58 0d 08 02 6f ?? 00 00 0a 09 59 13 04 11 04 8d ?? 00 00 01 13 05 06 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}