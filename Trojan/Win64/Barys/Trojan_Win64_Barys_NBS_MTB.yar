
rule Trojan_Win64_Barys_NBS_MTB{
	meta:
		description = "Trojan:Win64/Barys.NBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 6a 65 63 74 69 6e 67 20 3a 20 42 6f 6e 65 20 4e 65 63 6b 20 46 69 72 73 74 } //01 00  Injecting : Bone Neck First
		$a_01_1 = {41 69 6d 62 6f 74 20 53 63 6f 70 65 20 3a 20 45 6e 61 62 6c 65 64 } //01 00  Aimbot Scope : Enabled
		$a_01_2 = {52 65 73 65 74 69 6e 67 20 47 75 65 73 74 20 41 63 63 6f 75 6e 74 } //01 00  Reseting Guest Account
		$a_01_3 = {49 6e 6a 65 63 74 69 6e 67 20 42 79 70 61 73 73 20 2d 20 41 6e 74 69 63 68 65 61 74 2e 2e } //01 00  Injecting Bypass - Anticheat..
		$a_01_4 = {42 79 70 61 73 73 20 2d 20 41 6e 74 69 63 68 65 61 74 20 49 20 3a 20 49 6e 6a 65 63 74 65 64 21 } //01 00  Bypass - Anticheat I : Injected!
		$a_01_5 = {49 6e 6a 65 63 74 69 6e 67 20 41 69 6d 6e 65 63 6b 2e 2e } //01 00  Injecting Aimneck..
		$a_01_6 = {4e 70 63 20 4e 61 6d 65 3a 20 49 6e 6a 65 63 74 69 6e 67 } //01 00  Npc Name: Injecting
		$a_01_7 = {42 79 70 61 73 73 20 2d 20 41 6e 74 69 62 6c 61 63 6b 20 3a 20 49 6e 6a 65 63 74 65 64 21 } //00 00  Bypass - Antiblack : Injected!
	condition:
		any of ($a_*)
 
}