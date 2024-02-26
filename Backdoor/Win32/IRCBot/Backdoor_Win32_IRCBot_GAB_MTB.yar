
rule Backdoor_Win32_IRCBot_GAB_MTB{
	meta:
		description = "Backdoor:Win32/IRCBot.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 c7 85 90 01 04 3a 2f 2f 31 c7 85 90 01 04 36 37 2e 39 c7 85 90 01 04 39 2e 38 38 c7 85 90 01 04 2e 32 32 32 90 00 } //01 00 
		$a_01_1 = {53 68 75 74 64 6f 77 6e 20 70 61 73 73 77 6f 72 64 20 65 6e 74 65 72 65 64 20 2d 20 62 6f 74 6e 65 74 20 73 68 75 74 74 69 6e 67 20 64 6f 77 6e } //00 00  Shutdown password entered - botnet shutting down
	condition:
		any of ($a_*)
 
}