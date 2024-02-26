
rule Trojan_Win32_DarkGateLoader_MC_MTB{
	meta:
		description = "Trojan:Win32/DarkGateLoader.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 55 08 8b 52 f8 8b 4d 08 8a 49 f6 80 e1 03 c1 e1 06 8b 5d 08 8a 5b f7 80 e3 3f 02 cb 88 4c 10 ff 8b 45 08 ff 40 f8 8b c7 } //05 00 
		$a_01_1 = {7a 4c 41 78 75 55 30 6b 51 4b 66 33 73 57 45 37 65 50 52 4f 32 69 6d 79 67 39 47 53 70 56 6f 59 43 36 72 68 6c 58 34 38 5a 48 6e 76 6a 4a 44 42 4e 46 74 4d 64 31 49 35 61 63 77 62 71 54 2b 3d } //00 00  zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+=
	condition:
		any of ($a_*)
 
}