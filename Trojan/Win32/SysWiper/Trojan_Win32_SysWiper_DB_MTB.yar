
rule Trojan_Win32_SysWiper_DB_MTB{
	meta:
		description = "Trojan:Win32/SysWiper.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 0c 00 00 "
		
	strings :
		$a_81_0 = {4d 61 6c 77 61 72 65 53 74 61 72 74 75 70 } //20 MalwareStartup
		$a_81_1 = {6d 61 6c 77 61 72 65 2e 6c 6e 6b } //20 malware.lnk
		$a_81_2 = {4d 79 57 69 70 65 72 4d 61 6c 77 61 72 65 } //20 MyWiperMalware
		$a_81_3 = {4d 79 4d 61 6c 77 61 72 65 } //20 MyMalware
		$a_81_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_81_5 = {50 65 72 73 69 73 74 65 6e 63 65 20 61 64 64 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Persistence added successfully
		$a_81_6 = {46 72 65 65 20 64 69 73 6b 20 73 70 61 63 65 20 77 69 70 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Free disk space wiped successfully
		$a_81_7 = {45 72 72 6f 72 20 6f 70 65 6e 69 6e 67 20 70 68 79 73 69 63 61 6c 20 64 72 69 76 65 20 66 6f 72 20 4d 42 52 20 77 69 70 69 6e 67 } //1 Error opening physical drive for MBR wiping
		$a_81_8 = {45 72 72 6f 72 20 77 72 69 74 69 6e 67 20 74 6f 20 64 72 69 76 65 20 74 6f 20 77 69 70 65 20 4d 42 52 } //1 Error writing to drive to wipe MBR
		$a_81_9 = {65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 64 65 6c 65 74 65 64 } //1 encrypted and deleted
		$a_81_10 = {53 63 68 65 64 75 6c 65 64 20 74 61 73 6b 20 66 6f 72 20 70 65 72 73 69 73 74 65 6e 63 65 20 61 64 64 65 64 } //1 Scheduled task for persistence added
		$a_81_11 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e } //1 schtasks /create /tn
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=22
 
}