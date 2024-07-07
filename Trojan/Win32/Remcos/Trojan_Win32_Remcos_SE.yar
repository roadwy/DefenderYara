
rule Trojan_Win32_Remcos_SE{
	meta:
		description = "Trojan:Win32/Remcos.SE,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_81_0 = {55 70 6c 6f 61 64 69 6e 67 20 66 69 6c 65 20 74 6f 20 43 26 43 } //1 Uploading file to C&C
		$a_81_1 = {4f 66 66 6c 69 6e 65 20 4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64 } //1 Offline Keylogger Started
		$a_81_2 = {4f 66 66 6c 69 6e 65 20 4b 65 79 6c 6f 67 67 65 72 20 53 74 6f 70 70 65 64 } //1 Offline Keylogger Stopped
		$a_81_3 = {5b 46 6f 6c 6c 6f 77 69 6e 67 20 74 65 78 74 20 68 61 73 20 62 65 65 6e 20 70 61 73 74 65 64 20 66 72 6f 6d 20 63 6c 69 70 62 6f 61 72 64 3a 5d } //1 [Following text has been pasted from clipboard:]
		$a_81_4 = {5b 46 69 72 65 66 6f 78 20 53 74 6f 72 65 64 4c 6f 67 69 6e 73 20 63 6c 65 61 72 65 64 21 5d } //1 [Firefox StoredLogins cleared!]
		$a_81_5 = {5b 49 45 20 63 6f 6f 6b 69 65 73 20 6e 6f 74 20 66 6f 75 6e 64 5d } //1 [IE cookies not found]
		$a_81_6 = {4d 69 63 52 65 63 6f 72 64 73 } //1 MicRecords
		$a_80_7 = {52 65 6d 63 6f 73 } //Remcos  1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_80_7  & 1)*1) >=6
 
}