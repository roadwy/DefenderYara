
rule Backdoor_BAT_Remcos_KAAP_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.KAAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 5d 1f 90 01 01 58 1f 90 01 01 58 1f 90 01 01 59 91 61 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}