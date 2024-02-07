
rule Trojan_Win32_Repmord_A{
	meta:
		description = "Trojan:Win32/Repmord.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 69 64 65 6f 44 72 69 76 65 72 73 5c 47 50 55 5c 63 67 6d 69 6e 65 72 2e 65 78 65 } //01 00  VideoDrivers\GPU\cgminer.exe
		$a_01_1 = {47 50 55 5c 63 67 6d 69 6e 65 72 2e 65 78 65 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 20 2d 2d 73 63 72 79 70 74 20 2d 6f 20 73 74 72 61 74 75 6d 2b 74 63 70 3a } //01 00  GPU\cgminer.exe" & Chr(34) & " --scrypt -o stratum+tcp:
		$a_01_2 = {47 50 55 5c 72 75 6e 2e 76 62 73 22 20 2f 52 4c 20 48 49 47 48 45 53 54 } //00 00  GPU\run.vbs" /RL HIGHEST
	condition:
		any of ($a_*)
 
}