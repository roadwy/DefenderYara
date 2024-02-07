
rule Backdoor_BAT_Povbop_A{
	meta:
		description = "Backdoor:BAT/Povbop.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 4f 54 2e 46 6c 6f 6f 64 } //01 00  BOT.Flood
		$a_01_1 = {41 64 64 52 75 6e 64 6f 6d 46 6c 6f 6f 64 } //01 00  AddRundomFlood
		$a_01_2 = {41 74 74 61 63 6b } //01 00  Attack
		$a_01_3 = {3c 52 65 71 75 65 73 74 3e 62 5f 5f 65 } //01 00  <Request>b__e
		$a_01_4 = {2e 53 74 65 61 6c 46 69 6c 65 73 } //00 00  .StealFiles
	condition:
		any of ($a_*)
 
}