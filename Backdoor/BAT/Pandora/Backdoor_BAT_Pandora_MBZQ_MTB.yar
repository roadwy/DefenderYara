
rule Backdoor_BAT_Pandora_MBZQ_MTB{
	meta:
		description = "Backdoor:BAT/Pandora.MBZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 03 11 04 1f fe 28 ?? 00 00 0a 6f ?? 00 00 0a 1f ?? 28 ?? 00 00 0a 28 ?? 00 00 0a 08 11 05 09 5d 91 61 d2 9c 11 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}