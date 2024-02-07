
rule Backdoor_BAT_Xpress_B{
	meta:
		description = "Backdoor:BAT/Xpress.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 50 72 65 73 73 20 42 6f 74 5c 58 50 72 65 73 73 32 } //01 00  XPress Bot\XPress2
		$a_01_1 = {75 00 64 00 70 00 2e 00 66 00 6c 00 6f 00 6f 00 64 00 2f 00 65 00 78 00 65 00 63 00 2f 00 6b 00 69 00 6c 00 6c 00 } //00 00  udp.flood/exec/kill
	condition:
		any of ($a_*)
 
}