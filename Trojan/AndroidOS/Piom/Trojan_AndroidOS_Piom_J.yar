
rule Trojan_AndroidOS_Piom_J{
	meta:
		description = "Trojan:AndroidOS/Piom.J,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 61 74 20 52 65 63 6f 72 64 65 } //01 00  Stat Recorde
		$a_01_1 = {47 65 74 4e 65 77 43 61 6c 6c 54 68 72 } //01 00  GetNewCallThr
		$a_01_2 = {53 65 6e 64 53 4d 53 52 65 73 69 76 65 32 } //01 00  SendSMSResive2
		$a_01_3 = {77 73 73 3a 2f 2f 31 38 38 2e 34 30 2e 31 38 34 2e 31 34 31 3a 31 34 35 30 32 } //00 00  wss://188.40.184.141:14502
	condition:
		any of ($a_*)
 
}