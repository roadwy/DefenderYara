
rule Backdoor_BAT_Remcos_KAAS_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.KAAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 1f ?? 58 1f ?? 58 1f ?? 59 18 58 18 59 91 61 03 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}