
rule Trojan_Win32_Killav_KE{
	meta:
		description = "Trojan:Win32/Killav.KE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {64 65 6c 20 2f 51 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 6d 63 61 66 65 65 2e 63 6f 6d 5c 2a 2e 90 03 03 03 64 6c 6c 65 78 65 22 90 00 } //01 00 
		$a_00_1 = {64 65 6c 20 2f 51 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 53 79 6d 61 6e 74 65 63 5c 4c 69 76 65 55 70 64 61 74 65 5c 2a 2e 65 78 65 22 } //01 00  del /Q "C:\Program Files\Symantec\LiveUpdate\*.exe"
		$a_02_2 = {64 65 6c 20 2f 51 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 53 79 6d 61 6e 74 65 63 20 53 68 61 72 65 64 5c 2a 2e 90 03 03 03 64 6c 6c 65 78 65 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}