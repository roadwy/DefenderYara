
rule Backdoor_Win32_Prorat_AI{
	meta:
		description = "Backdoor:Win32/Prorat.AI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 5f 74 61 72 67 65 74 69 64 } //04 00  SOFTWARE\Microsoft\Windows\CurrentVersion\policies\_targetid
		$a_01_1 = {34 34 43 39 39 37 46 36 45 46 38 41 45 38 32 45 37 30 35 33 30 38 33 45 38 37 45 42 45 39 32 34 35 42 } //02 00  44C997F6EF8AE82E7053083E87EBE9245B
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 5f 6c 6f 61 64 6e 61 6d 65 } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\policies\_loadname
	condition:
		any of ($a_*)
 
}