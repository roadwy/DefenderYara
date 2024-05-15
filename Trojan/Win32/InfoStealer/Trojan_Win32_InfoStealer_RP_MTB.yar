
rule Trojan_Win32_InfoStealer_RP_MTB{
	meta:
		description = "Trojan:Win32/InfoStealer.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,53 00 53 00 0a 00 00 01 00 "
		
	strings :
		$a_80_0 = {73 65 61 77 79 72 6d } //seawyrm  01 00 
		$a_80_1 = {6b 6e 69 67 68 74 } //knight  01 00 
		$a_80_2 = {67 72 69 66 66 69 6e } //griffin  01 00 
		$a_80_3 = {53 65 61 20 57 79 72 6d } //Sea Wyrm  01 00 
		$a_80_4 = {4b 6e 69 67 68 74 } //Knight  01 00 
		$a_80_5 = {47 72 69 66 66 69 6e } //Griffin  14 00 
		$a_80_6 = {53 69 6d 75 6c 61 74 69 6f 6e 45 6e 67 69 6e 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //SimulationEngine.Properties.Resources  14 00 
		$a_80_7 = {63 61 73 74 6c 65 5f 77 69 6e 64 6f 77 } //castle_window  14 00 
		$a_80_8 = {4c 61 6b 65 5f 4a 75 6e 67 6c 65 } //Lake_Jungle  14 00 
		$a_80_9 = {53 53 55 49 5f 48 65 6c 70 44 69 61 67 72 61 6d 5f 41 6e 69 6d 61 74 69 6f 6e 31 } //SSUI_HelpDiagram_Animation1  00 00 
	condition:
		any of ($a_*)
 
}