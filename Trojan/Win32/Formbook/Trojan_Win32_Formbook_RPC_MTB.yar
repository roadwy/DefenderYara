
rule Trojan_Win32_Formbook_RPC_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 39 2c 2a 34 4c 04 12 34 05 2c 5e 34 f3 04 0c 88 04 39 41 3b cb 72 e7 } //00 00 
	condition:
		any of ($a_*)
 
}