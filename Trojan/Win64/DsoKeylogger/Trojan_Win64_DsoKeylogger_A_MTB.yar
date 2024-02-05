
rule Trojan_Win64_DsoKeylogger_A_MTB{
	meta:
		description = "Trojan:Win64/DsoKeylogger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 ff 08 75 0c 4c 8d 05 4a 1f 00 00 e9 a8 01 00 00 83 ff 0d 75 } //00 00 
	condition:
		any of ($a_*)
 
}