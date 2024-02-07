
rule TrojanClicker_BAT_Lasdoma_A_bit{
	meta:
		description = "TrojanClicker:BAT/Lasdoma.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6f 50 72 6f 74 65 63 74 6f 72 4d 61 6e 61 67 65 72 2e 65 78 65 } //01 00  EoProtectorManager.exe
		$a_01_1 = {6c 00 61 00 73 00 65 00 72 00 76 00 65 00 72 00 61 00 64 00 65 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 61 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 2f 00 } //01 00  laserveradedomaina.com/redirect/
		$a_01_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}