
rule Trojan_BAT_Chippedout_A_dha{
	meta:
		description = "Trojan:BAT/Chippedout.A!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 76 00 65 00 72 00 73 00 65 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 65 00 78 00 63 00 65 00 65 00 64 00 65 00 64 00 20 00 6c 00 69 00 66 00 65 00 74 00 69 00 6d 00 65 00 2e 00 20 00 53 00 68 00 75 00 74 00 74 00 69 00 6e 00 67 00 20 00 64 00 6f 00 77 00 6e 00 2e 00 } //01 00  Reverse shell exceeded lifetime. Shutting down.
		$a_01_1 = {43 00 68 00 69 00 70 00 6d 00 75 00 6e 00 6b 00 2e 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2e 00 43 00 6f 00 6d 00 6d 00 75 00 6e 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 64 00 6c 00 6c 00 } //01 00  Chipmunk.resources.Communication.dll
		$a_01_2 = {44 00 50 00 47 00 20 00 41 00 74 00 74 00 61 00 63 00 6b 00 20 00 54 00 65 00 61 00 6d 00 } //01 00  DPG Attack Team
		$a_01_3 = {45 00 52 00 52 00 4f 00 52 00 20 00 50 00 69 00 70 00 65 00 6c 00 69 00 6e 00 65 00 20 00 53 00 74 00 6f 00 70 00 70 00 65 00 64 00 3a 00 } //00 00  ERROR Pipeline Stopped:
	condition:
		any of ($a_*)
 
}