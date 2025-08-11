
rule Trojan_BAT_PureLogs_AC_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 29 03 00 04 20 4d a0 de 9b 20 ad eb 60 bd 58 20 fa 8b 3f 59 61 7d 2b 03 00 04 20 2f 00 00 00 fe 0e 00 00 38 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}