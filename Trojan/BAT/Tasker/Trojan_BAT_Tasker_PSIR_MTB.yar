
rule Trojan_BAT_Tasker_PSIR_MTB{
	meta:
		description = "Trojan:BAT/Tasker.PSIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 7e f8 01 00 04 7e f7 01 00 04 28 90 01 03 0a 28 90 01 03 0a 00 73 90 01 03 0a 0b 07 72 69 16 00 70 6f 90 01 03 0a 00 07 17 6f 90 01 03 0a 00 07 1b 8d 4c 00 00 01 25 16 72 83 16 00 70 a2 25 17 7e f7 01 00 04 28 90 01 03 0a a2 25 18 72 c7 16 00 70 a2 25 19 7e f8 01 00 04 a2 25 1a 72 d7 16 00 70 a2 28 90 01 03 0a 6f 90 01 03 0a 00 07 28 90 01 03 0a 0c 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}