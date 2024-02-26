
rule Trojan_Win32_Darkgate_IP_MTB{
	meta:
		description = "Trojan:Win32/Darkgate.IP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 4c 41 78 75 55 30 6b 51 4b 66 33 73 57 45 37 65 50 52 4f 32 69 6d 79 67 39 47 53 70 56 6f 59 43 36 72 68 6c 58 34 38 5a 48 6e 76 6a 4a 44 42 4e 46 74 4d 64 31 49 35 61 63 77 62 71 54 2b 3d } //01 00  zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+=
		$a_01_1 = {8a 1a 8a 4e 06 eb e8 8a 5c 31 06 32 1c 11 } //00 00 
	condition:
		any of ($a_*)
 
}