
rule Trojan_BAT_KillAV_NA_MTB{
	meta:
		description = "Trojan:BAT/KillAV.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 09 8e 69 09 16 7e 28 00 00 0a 16 7e 28 00 00 0a 28 04 00 00 06 2c 08 07 28 07 00 00 06 } //3
		$a_01_1 = {8d 07 00 00 02 13 06 07 12 04 12 05 11 06 12 07 28 05 00 00 06 26 07 17 7e 28 00 00 0a 28 06 00 00 06 26 2a } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}