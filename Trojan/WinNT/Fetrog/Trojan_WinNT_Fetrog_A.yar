
rule Trojan_WinNT_Fetrog_A{
	meta:
		description = "Trojan:WinNT/Fetrog.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {48 8b f9 48 03 fa 48 33 c0 8a 01 41 f6 e0 49 03 c1 88 01 48 33 c0 48 ff c1 48 3b cf 75 eb } //02 00 
		$a_01_1 = {80 39 eb 75 0c 48 0f be 41 01 48 8d 4c 08 02 eb 0e 80 39 e9 75 0e 48 63 41 01 48 8d 4c 08 05 b0 01 48 89 0a } //01 00 
		$a_00_2 = {4e 00 65 00 74 00 5f 00 55 00 31 00 6f 00 63 00 69 00 6b 00 65 00 2e 00 5f 00 32 00 6b 00 } //01 00  Net_U1ocike._2k
		$a_00_3 = {66 00 33 00 74 00 5f 00 30 00 67 00 2e 00 64 00 61 00 74 00 } //01 00  f3t_0g.dat
		$a_00_4 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 72 00 6d 00 70 00 64 00 6b 00 30 00 67 00 } //00 00  \DosDevices\rmpdk0g
		$a_00_5 = {80 } //10 00 
	condition:
		any of ($a_*)
 
}