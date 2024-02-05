
rule Backdoor_Win32_Pirpi_R_dha{
	meta:
		description = "Backdoor:Win32/Pirpi.R!dha,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0e 00 00 01 00 "
		
	strings :
		$a_80_0 = {54 72 75 73 74 55 64 70 53 65 72 76 65 72 3a 3a 5f 68 61 6e 64 6c 65 53 6e 69 66 66 65 72 52 65 71 75 65 73 74 } //TrustUdpServer::_handleSnifferRequest  01 00 
		$a_80_1 = {54 72 75 73 74 55 64 70 53 65 72 76 65 72 2e 63 70 70 } //TrustUdpServer.cpp  01 00 
		$a_80_2 = {43 4e 3d 4d 69 63 72 6f 73 6f 66 74 20 43 6f 72 70 6f 72 61 74 69 6f 6e 2c 4c 3d 52 65 64 6d 6f 6e 64 2c 53 3d 57 61 73 68 69 6e 67 74 6f 6e 2c 43 3d 55 53 } //CN=Microsoft Corporation,L=Redmond,S=Washington,C=US  01 00 
		$a_80_3 = {54 68 69 73 20 69 73 20 61 20 76 65 6e 64 6f 72 27 73 20 61 63 63 6f 75 6e 74 20 66 6f 72 20 74 68 65 20 48 65 6c 70 20 61 6e 64 20 53 75 70 70 6f 72 74 20 53 65 72 76 69 63 65 } //This is a vendor's account for the Help and Support Service  01 00 
		$a_80_4 = {54 68 69 73 20 69 73 20 61 20 4d 61 63 68 69 6e 65 20 61 63 63 6f 75 6e 74 20 66 6f 72 20 49 49 53 20 53 65 72 76 69 63 65 } //This is a Machine account for IIS Service  01 00 
		$a_80_5 = {41 42 43 55 44 45 46 5a 59 58 47 48 49 4a 54 4b 4c 4d 4e 4f 50 51 52 53 56 57 61 62 63 64 65 66 67 68 33 34 69 6a 6b 7a 79 78 6c 6d 6e 6f 72 73 74 75 76 77 30 31 32 35 36 37 70 71 38 39 2b 2f } //ABCUDEFZYXGHIJTKLMNOPQRSVWabcdefgh34ijkzyxlmnorstuvw012567pq89+/  01 00 
		$a_80_6 = {2d 73 65 72 76 65 72 50 } //-serverP  01 00 
		$a_80_7 = {43 6f 6d 6d 61 6e 64 50 61 72 73 65 72 3a 3a 70 61 72 73 65 43 6f 6d 6d 61 6e 64 } //CommandParser::parseCommand  01 00 
		$a_80_8 = {73 6e 69 66 66 65 72 5c 43 6f 6d 6d 61 6e 64 50 61 72 73 65 72 2e 63 70 70 } //sniffer\CommandParser.cpp  01 00 
		$a_80_9 = {43 6f 6d 6d 61 6e 64 50 61 72 73 65 72 3a 3a 5f 70 61 72 73 65 49 70 50 61 72 61 6d } //CommandParser::_parseIpParam  01 00 
		$a_80_10 = {48 69 64 65 4c 6f 61 64 64 65 72 2e 63 70 70 } //HideLoadder.cpp  01 00 
		$a_80_11 = {69 6e 76 61 6c 69 64 20 70 65 20 66 69 6c 65 2c 20 74 68 65 20 70 72 6f 67 72 61 6d 20 6d 75 73 74 20 62 65 20 25 64 20 62 69 74 } //invalid pe file, the program must be %d bit  01 00 
		$a_80_12 = {48 69 64 65 4c 6f 61 64 64 65 72 3a 3a 5f 70 65 41 6c 6c 6f 63 } //HideLoadder::_peAlloc  01 00 
		$a_80_13 = {48 69 64 65 4c 6f 61 64 64 65 72 3a 3a 5f 70 65 42 75 69 6c 64 } //HideLoadder::_peBuild  00 00 
	condition:
		any of ($a_*)
 
}