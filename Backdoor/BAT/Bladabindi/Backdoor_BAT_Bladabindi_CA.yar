
rule Backdoor_BAT_Bladabindi_CA{
	meta:
		description = "Backdoor:BAT/Bladabindi.CA,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 00 43 00 79 00 62 00 65 00 72 00 53 00 70 00 72 00 65 00 61 00 64 00 5d 00 } //01 00  [CyberSpread]
		$a_01_1 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 } //01 00  [autorun]
		$a_01_2 = {73 00 65 00 6e 00 64 00 66 00 69 00 6c 00 65 00 } //01 00  sendfile
		$a_01_3 = {72 65 73 74 61 72 74 } //01 00  restart
		$a_01_4 = {75 73 62 5f 73 70 } //00 00  usb_sp
	condition:
		any of ($a_*)
 
}