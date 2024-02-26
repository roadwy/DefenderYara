
rule Trojan_Win32_DarkGate_CCDC_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.CCDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 4c 41 78 75 55 30 6b 51 4b 66 33 73 57 45 37 65 50 52 4f 32 69 6d 79 67 39 47 53 70 56 6f 59 43 36 72 68 6c 58 34 38 5a 48 6e 76 6a 4a 44 42 4e 46 74 4d 64 31 49 35 61 63 77 62 71 54 2b 3d } //01 00  zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+=
		$a_01_1 = {5c 64 61 74 61 2e 62 69 6e } //01 00  \data.bin
		$a_01_2 = {4a 75 6d 70 49 44 28 22 22 2c 22 25 73 22 29 } //00 00  JumpID("","%s")
	condition:
		any of ($a_*)
 
}