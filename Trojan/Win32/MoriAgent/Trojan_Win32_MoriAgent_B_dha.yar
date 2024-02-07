
rule Trojan_Win32_MoriAgent_B_dha{
	meta:
		description = "Trojan:Win32/MoriAgent.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 72 79 74 78 6e 5a 44 36 4d 2b 58 61 38 69 6d 31 71 66 64 67 6a 37 6b 48 63 70 59 62 4f 49 55 30 56 32 52 43 4a 68 6f 57 4b 51 53 77 50 42 46 65 34 7a 45 75 6c 76 35 54 33 47 41 4c } //01 00  NrytxnZD6M+Xa8im1qfdgj7kHcpYbOIU0V2RCJhoWKQSwPBFe4zEulv5T3GAL
		$a_01_1 = {4a 6d 33 51 6b 6a 52 70 4d 46 32 4b 2b 47 62 76 63 6f 31 58 68 43 49 41 4e 66 77 75 61 37 57 59 39 45 74 78 67 48 6c 54 7a 4f 5a 56 34 38 50 36 71 44 53 6e 42 72 69 35 79 64 4c 65 30 } //00 00  Jm3QkjRpMF2K+Gbvco1XhCIANfwua7WY9EtxgHlTzOZV48P6qDSnBri5ydLe0
	condition:
		any of ($a_*)
 
}