
rule Backdoor_BAT_Remcos_APMA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.APMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 fe 0c 01 00 8f ?? 00 00 01 25 47 fe 09 00 00 fe 0c 01 00 fe 09 00 00 8e 69 5d 91 61 d2 52 00 fe 0c 01 00 20 01 00 00 00 58 fe 0e 01 00 fe 0c 01 00 fe 0c 00 00 8e 69 fe 04 fe 0e 02 00 fe 0c 02 00 3a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}