
rule Trojan_Win32_Qbot_DSK_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 0c 0f 66 89 74 24 42 8b 74 24 1c 8b 3c 24 32 0c 3e 8b 74 24 20 8b 7c 24 0c 88 0c 3e } //02 00 
		$a_01_1 = {8a 1c 37 8b 74 24 18 32 1c 0e 8b 4c 24 1c 8b 74 24 04 88 1c 31 } //00 00 
	condition:
		any of ($a_*)
 
}