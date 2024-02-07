
rule Trojan_Win64_CobaltStrike_PCB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PCB!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 44 15 fb 8b 4d f7 32 c8 88 4c 15 fb 48 ff c2 48 83 fa 3c 72 e9 } //01 00 
		$a_01_1 = {41 0f b6 42 02 0f b6 0c 38 41 0f b6 42 03 49 83 c2 04 c0 e1 06 0a 0c 38 41 88 49 02 49 83 c1 03 48 83 eb 01 } //01 00 
		$a_01_2 = {77 69 6e 64 6f 77 73 2e 69 6e 69 } //00 00  windows.ini
	condition:
		any of ($a_*)
 
}