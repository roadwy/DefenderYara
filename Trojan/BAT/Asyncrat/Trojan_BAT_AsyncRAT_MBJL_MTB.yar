
rule Trojan_BAT_AsyncRAT_MBJL_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 e1 31 06 70 a2 25 17 72 e7 31 06 70 a2 0a 06 16 9a 06 17 9a 28 90 01 01 00 00 0a 72 ed 31 06 70 15 16 90 00 } //01 00 
		$a_03_1 = {72 f3 31 06 70 15 16 28 90 01 01 00 00 0a 0b 16 0c 2b 2d 07 08 9a 0d 06 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}