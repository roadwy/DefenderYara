
rule Backdoor_BAT_AsyncRAT_N_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 0c 06 08 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 18 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 13 04 02 0d 90 00 } //02 00 
		$a_03_1 = {0a 0a 08 06 6f 90 01 01 00 00 0a 0a 73 90 01 01 00 00 0a 0d 06 13 06 16 13 05 2b 20 11 06 11 05 91 13 04 09 12 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}