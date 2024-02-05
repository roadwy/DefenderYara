
rule Backdoor_BAT_AsyncRAT_NE_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 1e 5a 1e 6f 90 01 01 00 00 0a 18 28 90 01 01 00 00 0a 9c 08 17 58 0c 08 07 8e 69 17 59 31 e1 90 00 } //01 00 
		$a_01_1 = {52 61 79 43 72 79 35 2e 32 } //00 00 
	condition:
		any of ($a_*)
 
}