
rule Trojan_BAT_KillMBR_EHM_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.EHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 20 f8 2f 14 00 8d 15 00 00 01 0a 16 0b 2b 15 06 07 02 07 6f 19 00 00 0a 20 00 01 00 00 5d d2 9c 07 17 58 0b 07 20 f8 2f 14 00 32 e3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}