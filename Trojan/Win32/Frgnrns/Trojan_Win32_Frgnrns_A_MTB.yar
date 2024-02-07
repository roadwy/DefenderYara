
rule Trojan_Win32_Frgnrns_A_MTB{
	meta:
		description = "Trojan:Win32/Frgnrns.A!MTB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 21 5d 43 61 6e 74 20 67 65 74 20 63 70 75 20 6e 61 6d 65 2e } //01 00  [!]Cant get cpu name.
		$a_01_1 = {5b 21 5d 45 72 72 6f 72 20 67 65 74 74 69 6e 67 20 6d 65 6d 6f 72 79 2e } //01 00  [!]Error getting memory.
		$a_01_2 = {5b 21 5d 43 61 6e 74 20 67 65 74 20 70 72 6f 63 65 73 73 20 6e 61 6d 65 73 2e } //01 00  [!]Cant get process names.
		$a_01_3 = {41 6c 72 65 64 79 20 72 75 6e 6e 69 6e 67 } //01 00  Alredy running
		$a_01_4 = {5b 21 5d 20 57 53 41 53 74 61 72 74 75 70 20 65 72 72 6f 72 3a 20 25 69 } //01 00  [!] WSAStartup error: %i
		$a_01_5 = {5b 2b 5d 20 43 6f 6e 6e 65 63 74 20 74 6f 20 53 65 72 76 65 72 20 73 75 63 63 65 73 73 } //01 00  [+] Connect to Server success
		$a_01_6 = {5b 2b 5d 43 6f 6d 6d 61 6e 64 20 73 74 6f 70 20 72 65 76 65 72 73 65 20 70 72 6f 78 79 2e } //01 00  [+]Command stop reverse proxy.
		$a_01_7 = {5b 2b 5d 43 6f 6d 6d 61 6e 64 20 73 74 61 72 74 20 72 65 76 65 72 73 65 20 70 72 6f 78 79 2e } //01 00  [+]Command start reverse proxy.
		$a_01_8 = {5b 21 5d 52 65 76 65 72 73 65 20 70 72 6f 78 79 20 61 6c 72 65 61 64 79 20 73 74 61 72 74 65 64 } //01 00  [!]Reverse proxy already started
		$a_01_9 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c } //01 00  \AppData\Local\Google\Chrome\User Data\Default\
		$a_01_10 = {5b 21 5d 20 43 6f 6e 6e 65 63 74 20 74 6f 20 53 65 72 76 65 72 20 65 72 72 6f 72 } //01 00  [!] Connect to Server error
		$a_01_11 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_12 = {53 00 6f 00 6d 00 65 00 4b 00 65 00 79 00 } //00 00  SomeKey
	condition:
		any of ($a_*)
 
}