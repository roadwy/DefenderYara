
rule Trojan_BAT_NexilBreak_B_dha{
	meta:
		description = "Trojan:BAT/NexilBreak.B!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 00 6f 00 6d 00 69 00 6e 00 61 00 74 00 65 00 64 00 2e 00 52 00 6f 00 75 00 74 00 65 00 } //1 Dominated.Route
		$a_01_1 = {4d 00 6f 00 64 00 65 00 72 00 61 00 74 00 6f 00 72 00 2e 00 52 00 6f 00 75 00 74 00 65 00 } //1 Moderator.Route
		$a_01_2 = {65 00 72 00 72 00 2e 00 6c 00 6f 00 67 00 } //1 err.log
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}