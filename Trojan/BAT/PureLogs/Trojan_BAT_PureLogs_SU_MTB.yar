
rule Trojan_BAT_PureLogs_SU_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {12 00 28 0b 00 00 0a 0b 0f 02 28 0c 00 00 0a 39 07 00 00 00 16 0c dd 33 00 00 00 07 03 04 05 6f 03 00 00 06 3a 07 00 00 00 16 0c dd 1e 00 00 00 12 00 28 0d 00 00 0a 2d c7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}