
rule Trojan_BAT_KillWin_SWR_MTB{
	meta:
		description = "Trojan:BAT/KillWin.SWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 75 73 5f 44 65 73 74 72 75 63 74 69 76 65 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 56 69 72 75 73 5f 44 65 73 74 72 75 63 74 69 76 65 2e 70 64 62 } //2 Virus_Destructive\obj\Release\Virus_Destructive.pdb
		$a_01_1 = {74 6d 72 5f 6e 65 78 74 5f 70 61 79 6c 6f 61 64 5f 54 69 63 6b } //1 tmr_next_payload_Tick
		$a_01_2 = {24 36 62 36 31 32 36 31 31 2d 64 38 66 34 2d 34 66 30 66 2d 61 31 35 38 2d 34 33 64 31 35 62 66 35 64 35 35 37 } //1 $6b612611-d8f4-4f0f-a158-43d15bf5d557
		$a_01_3 = {56 69 72 75 73 5f 44 65 73 74 72 75 63 74 69 76 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Virus_Destructive.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}