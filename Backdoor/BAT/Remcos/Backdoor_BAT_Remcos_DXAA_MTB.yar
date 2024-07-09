
rule Backdoor_BAT_Remcos_DXAA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.DXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 13 06 11 05 13 07 11 06 11 07 11 06 11 07 6f ?? 00 00 0a 06 11 05 06 8e 69 5d 91 61 d2 6f ?? 00 00 0a 00 00 11 05 17 58 13 05 11 05 03 6f ?? 00 00 0a fe 04 13 08 11 08 2d c4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}