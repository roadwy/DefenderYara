
rule Trojan_O97M_Prenebevs{
	meta:
		description = "Trojan:O97M/Prenebevs,SIGNATURE_TYPE_MACROHSTR_EXT,32 00 32 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {45 6e 76 69 72 6f 6e 28 22 53 59 53 54 45 4d 44 52 49 56 45 22 29 } //0a 00  Environ("SYSTEMDRIVE")
		$a_00_1 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 4d 49 4e 55 54 45 20 2f 74 6e 20 22 22 47 6f 6f 67 6c 65 55 70 64 61 74 65 54 61 73 6b 73 4d 61 63 68 69 6e 65 43 6f 72 65 22 22 } //0a 00  schtasks /create /sc MINUTE /tn ""GoogleUpdateTasksMachineCore""
		$a_00_2 = {5c 22 22 73 63 5c 22 22 72 5c 22 22 69 5c 22 22 70 5c 22 22 74 3a 68 74 74 70 3a 2f 2f 38 30 2e 32 35 35 2e 33 2e 31 30 39 2f 6d 69 63 72 6f 73 6f 66 74 2e 6a 73 } //0a 00  \""sc\""r\""i\""p\""t:http://80.255.3.109/microsoft.js
		$a_00_3 = {28 22 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 22 29 } //0a 00  ("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentVersion")
		$a_02_4 = {46 69 6c 65 43 6f 70 79 20 90 02 20 20 26 20 22 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 77 73 63 72 69 70 74 2e 65 78 65 22 2c 90 00 } //00 00 
		$a_00_5 = {5d 04 00 00 cd a9 03 80 5c 38 00 00 ce a9 03 80 00 00 01 00 06 00 22 00 42 61 63 6b 64 6f 6f 72 3a 50 6f 77 65 72 53 68 65 6c 6c 2f 50 6f 77 64 6f 6f } //72 6d 
	condition:
		any of ($a_*)
 
}