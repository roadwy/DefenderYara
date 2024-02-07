
rule Trojan_BAT_SnakeKeylogger_DX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 44 44 44 44 44 44 46 } //01 00  FDDDDDDF
		$a_81_1 = {49 49 49 49 49 75 61 73 49 49 49 49 49 49 } //01 00  IIIIIuasIIIIII
		$a_81_2 = {54 72 69 70 6c 65 44 45 53 } //01 00  TripleDES
		$a_81_3 = {52 75 6e 50 6f 77 65 72 53 68 65 6c 6c } //01 00  RunPowerShell
		$a_81_4 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_5 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_7 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}