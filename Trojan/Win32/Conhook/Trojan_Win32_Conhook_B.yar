
rule Trojan_Win32_Conhook_B{
	meta:
		description = "Trojan:Win32/Conhook.B,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1e 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {45 78 65 63 75 74 65 00 53 68 6f 77 55 72 6c 00 4e 65 77 57 69 6e 64 6f 77 00 00 00 48 69 64 64 65 6e 57 69 6e 64 6f 77 } //0a 00 
		$a_02_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 90 02 06 53 68 75 74 64 6f 77 6e 00 90 02 06 53 74 61 72 74 75 70 90 00 } //0a 00 
		$a_00_2 = {64 00 75 00 6e 00 63 00 61 00 6e 00 5f 00 6e 00 61 00 76 00 69 00 67 00 61 00 74 00 65 00 72 00 } //01 00  duncan_navigater
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 61 66 25 30 38 78 } //00 00  Software\Microsoft\af%08x
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Conhook_B_2{
	meta:
		description = "Trojan:Win32/Conhook.B,SIGNATURE_TYPE_PEHSTR_EXT,24 00 23 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {45 78 65 63 75 74 65 00 53 68 6f 77 55 72 6c 00 4e 65 77 57 69 6e 64 6f 77 00 00 00 48 69 64 64 65 6e 57 69 6e 64 6f 77 } //0a 00 
		$a_00_1 = {44 75 6e 63 61 6e } //0a 00  Duncan
		$a_02_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 90 02 06 53 68 75 74 64 6f 77 6e 00 90 02 06 53 74 61 72 74 75 70 90 00 } //05 00 
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 73 74 72 35 } //05 00  SOFTWARE\Microsoft\Dstr5
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 49 6e 66 } //05 00  Software\Microsoft\DInf
		$a_00_5 = {41 4e 54 49 53 50 59 57 41 52 45 3f 47 43 41 53 53 45 52 56 41 4c 45 52 54 2e 45 58 45 } //01 00  ANTISPYWARE?GCASSERVALERT.EXE
		$a_00_6 = {53 68 6f 77 20 68 69 64 65 6e 20 70 6f 70 75 70 3a } //01 00  Show hiden popup:
		$a_00_7 = {7b 34 30 39 31 30 42 43 46 2d 30 42 30 32 2d 34 31 37 65 2d 38 43 38 31 2d 42 43 32 31 32 34 33 37 36 31 33 33 7d } //00 00  {40910BCF-0B02-417e-8C81-BC2124376133}
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Conhook_B_3{
	meta:
		description = "Trojan:Win32/Conhook.B,SIGNATURE_TYPE_PEHSTR_EXT,37 00 35 00 0b 00 00 0a 00 "
		
	strings :
		$a_00_0 = {44 75 6e 63 61 6e 4d 75 74 65 78 } //0a 00  DuncanMutex
		$a_01_1 = {55 70 61 63 6b 42 79 44 77 69 6e 67 } //0a 00  UpackByDwing
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //0a 00  SOFTWARE\Microsoft\Internet Explorer
		$a_00_3 = {4b 65 72 69 6f 50 65 72 73 6f 6e 61 6c 46 69 72 65 77 61 6c 6c 53 65 72 76 65 72 } //0a 00  KerioPersonalFirewallServer
		$a_00_4 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  http\shell\open\command
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 49 6e 66 } //01 00  Software\Microsoft\DInf
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 6d 66 63 6f 73 } //01 00  Software\mfcos
		$a_00_7 = {68 74 74 70 3a 2f 2f 38 35 2e 31 37 2e 33 2e 31 35 31 2f 63 67 69 2d 62 69 6e } //01 00  http://85.17.3.151/cgi-bin
		$a_00_8 = {68 74 74 70 3a 2f 2f 38 33 2e 31 34 39 2e 37 35 2e 35 34 2f 63 67 69 2d 62 69 6e } //01 00  http://83.149.75.54/cgi-bin
		$a_00_9 = {25 73 2f 61 73 64 33 3f 41 66 66 3d 25 73 3f 63 3d 25 73 2b 25 73 26 72 6f 76 3d 25 73 } //01 00  %s/asd3?Aff=%s?c=%s+%s&rov=%s
		$a_00_10 = {46 37 45 45 33 44 46 38 2d 41 39 44 30 2d 34 37 66 32 2d 39 34 39 34 2d 34 44 44 45 30 42 32 46 30 34 37 35 } //00 00  F7EE3DF8-A9D0-47f2-9494-4DDE0B2F0475
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Conhook_B_4{
	meta:
		description = "Trojan:Win32/Conhook.B,SIGNATURE_TYPE_PEHSTR_EXT,37 00 35 00 0b 00 00 0a 00 "
		
	strings :
		$a_00_0 = {44 75 6e 63 61 6e 4d 75 74 65 78 } //0a 00  DuncanMutex
		$a_01_1 = {55 70 61 63 6b 42 79 44 77 69 6e 67 } //0a 00  UpackByDwing
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //0a 00  SOFTWARE\Microsoft\Internet Explorer
		$a_01_3 = {4b 65 72 69 6f 50 65 72 73 6f 6e 61 6c 46 69 72 65 77 61 6c 6c 53 65 72 76 65 72 } //0a 00  KerioPersonalFirewallServer
		$a_00_4 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  http\shell\open\command
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 49 6e 66 } //01 00  Software\Microsoft\DInf
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 6d 66 63 6f 73 } //01 00  Software\mfcos
		$a_00_7 = {68 74 74 70 3a 2f 2f 38 35 2e 31 37 2e 33 2e 31 35 31 2f 63 67 69 2d 62 69 6e } //01 00  http://85.17.3.151/cgi-bin
		$a_00_8 = {68 74 74 70 3a 2f 2f 38 33 2e 31 34 39 2e 37 35 2e 35 34 2f 63 67 69 2d 62 69 6e } //01 00  http://83.149.75.54/cgi-bin
		$a_00_9 = {25 73 2f 61 73 64 33 3f 41 66 66 3d 25 73 3f 63 3d 25 73 2b 25 73 26 72 6f 76 3d 25 73 } //01 00  %s/asd3?Aff=%s?c=%s+%s&rov=%s
		$a_00_10 = {46 37 45 45 33 44 46 38 2d 41 39 44 30 2d 34 37 66 32 2d 39 34 39 34 2d 34 44 44 45 30 42 32 46 30 34 37 35 } //00 00  F7EE3DF8-A9D0-47f2-9494-4DDE0B2F0475
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Conhook_B_5{
	meta:
		description = "Trojan:Win32/Conhook.B,SIGNATURE_TYPE_PEHSTR,20 00 1f 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 75 6e 63 61 6e 4d 75 74 65 78 } //0a 00  DuncanMutex
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 73 74 72 35 } //0a 00  SOFTWARE\Microsoft\Dstr5
		$a_01_2 = {48 69 64 64 65 6e 57 69 6e 64 6f 77 } //01 00  HiddenWindow
		$a_01_3 = {44 75 6e 63 61 6e 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //01 00  畄据湡搮汬䐀汬慃啮汮慯乤睯
		$a_01_4 = {41 4e 54 49 53 50 59 57 41 52 45 3f 47 43 41 53 53 45 52 56 41 4c 45 52 54 2e 45 58 45 } //01 00  ANTISPYWARE?GCASSERVALERT.EXE
		$a_01_5 = {7b 34 30 39 31 30 42 43 46 2d 30 42 30 32 2d 34 31 37 65 2d 38 43 38 31 2d 42 43 32 31 32 34 33 37 36 31 33 33 7d } //01 00  {40910BCF-0B02-417e-8C81-BC2124376133}
		$a_01_6 = {4f 6e 53 68 75 74 64 6f 77 6e 00 4f 6e 53 74 61 72 74 75 70 00 52 75 6e 00 53 65 74 75 70 } //01 00  湏桓瑵潤湷伀卮慴瑲灵刀湵匀瑥灵
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 52 61 73 61 70 32 4b } //00 00  Software\Microsoft\Rasap2K
	condition:
		any of ($a_*)
 
}