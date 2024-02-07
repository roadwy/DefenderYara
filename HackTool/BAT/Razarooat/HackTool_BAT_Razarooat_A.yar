
rule HackTool_BAT_Razarooat_A{
	meta:
		description = "HackTool:BAT/Razarooat.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 44 00 6f 00 53 00 20 00 41 00 74 00 74 00 61 00 63 00 6b 00 } //01 00  DDoS Attack
		$a_01_1 = {53 00 4c 00 4f 00 57 00 53 00 54 00 41 00 52 00 54 00 } //01 00  SLOWSTART
		$a_01_2 = {7c 00 4c 00 4d 00 6d 00 61 00 72 00 6b 00 7c 00 } //01 00  |LMmark|
		$a_01_3 = {52 00 61 00 7a 00 61 00 72 00 20 00 52 00 41 00 54 00 } //01 00  Razar RAT
		$a_01_4 = {62 00 69 00 74 00 63 00 6f 00 69 00 6e 00 53 00 45 00 4e 00 44 00 } //00 00  bitcoinSEND
	condition:
		any of ($a_*)
 
}