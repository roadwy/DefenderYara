
rule TrojanSpy_BAT_Omaneat_B{
	meta:
		description = "TrojanSpy:BAT/Omaneat.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 48 6f 73 74 3e 28 2e 2b 3f 29 3c 2f 48 6f 73 74 3e 5c 73 2b 2e 2b 5c 73 2b 2e 2b 5c 73 2b 2e 2b 5c 73 2b 3c 55 73 65 72 3e 28 2e 2b 3f 29 3c 2f 55 73 65 72 3e 5c 73 2b 3c 50 61 73 73 3e 28 2e 2b 3f 29 3c 2f 50 61 73 73 3e } //01 00  <Host>(.+?)</Host>\s+.+\s+.+\s+.+\s+<User>(.+?)</User>\s+<Pass>(.+?)</Pass>
		$a_01_1 = {46 55 43 4b 55 50 } //01 00  FUCKUP
		$a_01_2 = {49 6e 73 74 61 6c 6c 65 64 20 4d 69 6e 65 72 20 53 75 63 63 65 73 73 66 75 6c 6c 79 21 20 4d 69 6e 65 72 20 49 44 3a 20 } //01 00  Installed Miner Successfully! Miner ID: 
		$a_01_3 = {43 61 6e 6e 6f 74 20 52 65 61 64 20 53 61 76 65 64 20 4b 65 79 6c 6f 67 3a 20 } //01 00  Cannot Read Saved Keylog: 
		$a_01_4 = {2a 53 74 61 72 74 65 64 2a 42 59 54 33 53 2a } //01 00  *Started*BYT3S*
		$a_01_5 = {3d 50 34 43 4b 33 54 3d } //01 00  =P4CK3T=
		$a_01_6 = {4e 4f 7c 43 52 59 50 54 } //01 00  NO|CRYPT
		$a_01_7 = {47 34 41 52 44 31 41 4e } //01 00  G4ARD1AN
		$a_01_8 = {2a 30 2a 44 45 43 49 44 45 2a 51 75 65 75 65 64 2a } //01 00  *0*DECIDE*Queued*
		$a_01_9 = {3d 46 6f 6c 64 65 72 3d 4e 2f 41 3d } //01 00  =Folder=N/A=
		$a_01_10 = {44 65 73 74 72 6f 79 50 43 } //01 00  DestroyPC
		$a_01_11 = {50 72 6f 61 63 74 69 76 65 20 41 6e 74 69 2d 4d 61 6c 77 61 72 65 20 63 6f 75 6c 64 20 6e 6f 74 20 62 65 20 65 6e 61 62 6c 65 64 20 62 65 63 61 75 73 65 20 74 68 69 73 20 63 6c 69 65 6e 74 20 64 6f 65 73 20 6e 6f 74 20 75 73 65 20 4c 75 6d 69 6e 6f 73 69 74 79 27 73 20 73 74 61 72 74 75 70 21 } //00 00  Proactive Anti-Malware could not be enabled because this client does not use Luminosity's startup!
		$a_00_12 = {7e 15 00 } //00 4c 
	condition:
		any of ($a_*)
 
}