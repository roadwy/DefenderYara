
rule Trojan_BAT_AgentTesla_JPO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0d 09 3a 90 00 } //01 00 
		$a_81_1 = {67 61 6d 65 6f 76 65 72 6c 61 79 75 69 2e 65 78 65 } //01 00  gameoverlayui.exe
		$a_81_2 = {54 65 6c 65 67 72 61 6d 20 46 5a 2d 4c 4c 43 } //00 00  Telegram FZ-LLC
	condition:
		any of ($a_*)
 
}