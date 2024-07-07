
rule Backdoor_BAT_Pandora_MBZQ_MTB{
	meta:
		description = "Backdoor:BAT/Pandora.MBZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 03 11 04 1f fe 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 1f 90 01 01 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 08 11 05 09 5d 91 61 d2 9c 11 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}