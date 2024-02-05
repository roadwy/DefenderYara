
rule Trojan_Win32_Hancitor_GG_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 08 00 00 0a 00 "
		
	strings :
		$a_80_0 = {4d 41 53 53 4c 6f 61 64 65 72 2e 64 6c 6c } //MASSLoader.dll  01 00 
		$a_80_1 = {5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //\System32\svchost.exe  01 00 
		$a_80_2 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //explorer.exe  01 00 
		$a_80_3 = {52 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 20 73 74 61 72 74 } //Rundll32.exe %s, start  01 00 
		$a_80_4 = {68 74 74 70 3a 2f 2f 61 70 69 2e 69 70 69 66 79 2e 6f 72 67 } //http://api.ipify.org  01 00 
		$a_80_5 = {47 55 49 44 3d 25 49 36 34 75 26 42 55 49 4c 44 3d 25 73 26 49 4e 46 4f 3d 25 73 26 45 58 54 3d 25 73 26 49 50 3d 25 73 26 54 59 50 45 3d 31 26 57 49 4e 3d 25 64 2e 25 64 } //GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d  01 00 
		$a_80_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  01 00 
		$a_80_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //WriteProcessMemory  00 00 
	condition:
		any of ($a_*)
 
}