
rule Trojan_Win32_NetWire_RA_MTB{
	meta:
		description = "Trojan:Win32/NetWire.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 88 28 32 9f 00 40 3b f8 77 f5 } //01 00 
		$a_01_1 = {33 0c 83 8b 55 08 8b 45 f8 89 0c 82 } //01 00 
		$a_01_2 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00 
		$a_01_3 = {69 70 63 6f 6e 66 69 67 2e 65 78 65 } //00 00 
		$a_00_4 = {78 69 00 } //00 07 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NetWire_RA_MTB_2{
	meta:
		description = "Trojan:Win32/NetWire.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_80_0 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4c 6f 67 73 5c } //AppData\Roaming\Logs\  01 00 
		$a_80_1 = {48 6f 73 74 49 64 2d } //HostId-  03 00 
		$a_80_2 = {48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4e 65 74 57 69 72 65 } //HKCU\SOFTWARE\NetWire  01 00 
		$a_80_3 = {49 6e 73 74 61 6c 6c 20 44 61 74 65 } //Install Date  01 00 
		$a_80_4 = {44 41 52 4b 45 59 45 44 } //DARKEYED  00 00 
		$a_00_5 = {78 07 01 00 } //0a 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NetWire_RA_MTB_3{
	meta:
		description = "Trojan:Win32/NetWire.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 65 6e 64 42 75 67 43 6f 6e 6e 65 63 74 5f 43 6c 69 63 6b } //01 00 
		$a_81_1 = {42 75 67 72 65 70 6f 72 74 74 78 74 } //01 00 
		$a_81_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00 
		$a_81_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 57 6f 77 36 34 5c 44 58 41 6e 69 6d 61 74 65 64 47 49 46 2e 6f 63 61 } //01 00 
		$a_81_4 = {6d 61 69 6c 74 6f 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00 
		$a_81_5 = {68 6d 6d 61 70 69 2e 70 64 62 } //01 00 
		$a_81_6 = {46 69 6c 65 45 6e 44 65 63 72 79 70 74 6f 72 20 28 75 73 65 73 20 52 43 34 20 66 6f 72 20 65 6e 64 65 63 72 79 70 74 69 6f 6e 29 } //01 00 
		$a_81_7 = {5c 52 63 34 63 6f 6e 66 69 67 2e 69 6e 69 } //01 00 
		$a_81_8 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //01 00 
		$a_81_9 = {52 65 67 45 6e 75 6d 4b 65 79 45 78 41 } //00 00 
	condition:
		any of ($a_*)
 
}