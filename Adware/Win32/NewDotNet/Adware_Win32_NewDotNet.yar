
rule Adware_Win32_NewDotNet{
	meta:
		description = "Adware:Win32/NewDotNet,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 } //01 00  Microsoft Visual C++ Runtime Library
		$a_01_1 = {63 6c 69 65 6e 74 2e 6e 65 77 2e 74 65 63 68 2e 6e 65 77 2e 6e 65 74 } //01 00  client.new.tech.new.net
		$a_01_2 = {6e 6e 72 75 6e 2e 65 78 65 } //01 00  nnrun.exe
		$a_01_3 = {41 46 38 36 33 37 42 30 2d 31 38 45 33 2d 34 34 44 33 2d 38 36 42 37 2d 35 35 45 30 39 44 39 43 34 32 36 31 } //01 00  AF8637B0-18E3-44D3-86B7-55E09D9C4261
		$a_01_4 = {6e 6e 63 6f 72 65 2e 64 6c 6c } //01 00  nncore.dll
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_6 = {4f 70 65 6e 53 43 4d 61 6e 61 67 65 72 41 } //01 00  OpenSCManagerA
		$a_01_7 = {43 72 65 61 74 65 53 65 72 76 69 63 65 41 } //01 00  CreateServiceA
		$a_01_8 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00  InternetOpenUrlA
		$a_01_9 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //00 00  GetClipboardData
	condition:
		any of ($a_*)
 
}
rule Adware_Win32_NewDotNet_2{
	meta:
		description = "Adware:Win32/NewDotNet,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4e 65 77 2e 6e 65 74 } //01 00  Software\New.net
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 4e 65 77 2e 6e 65 74 } //01 00  Software\Microsoft\Windows\CurrentVersion\Uninstall\New.net
		$a_01_2 = {4e 65 77 2e 6e 65 74 20 53 74 61 72 74 75 70 } //01 00  New.net Startup
		$a_01_3 = {72 75 6e 64 6c 6c 33 32 20 25 73 2c 4e 65 77 44 6f 74 4e 65 74 53 74 61 72 74 75 70 } //01 00  rundll32 %s,NewDotNetStartup
		$a_01_4 = {4e 65 77 44 6f 74 4e 65 74 43 6c 61 73 73 } //01 00  NewDotNetClass
		$a_01_5 = {5c 4e 65 77 44 6f 74 4e 65 74 5c } //01 00  \NewDotNet\
		$a_01_6 = {7b 44 44 35 32 31 41 31 44 2d 31 46 39 38 2d 31 31 44 34 2d 39 36 37 36 2d 30 30 45 30 31 38 39 38 31 42 39 45 7d } //01 00  {DD521A1D-1F98-11D4-9676-00E018981B9E}
		$a_01_7 = {7b 35 42 43 32 37 38 36 31 2d 33 31 34 41 2d 31 31 44 36 2d 39 39 36 44 2d 30 30 45 30 31 38 39 38 31 42 39 45 7d } //01 00  {5BC27861-314A-11D6-996D-00E018981B9E}
		$a_01_8 = {7b 34 41 32 41 41 43 46 33 2d 41 44 46 36 2d 31 31 44 35 2d 39 38 41 39 2d 30 30 45 30 31 38 39 38 31 42 39 45 7d } //01 00  {4A2AACF3-ADF6-11D5-98A9-00E018981B9E}
		$a_01_9 = {54 6c 64 63 74 6c 32 2e 55 52 4c 4c 69 6e 6b } //01 00  Tldctl2.URLLink
		$a_01_10 = {54 6c 64 63 74 6c 32 2e 55 52 4c 4c 69 6e 6b 2e 31 } //01 00  Tldctl2.URLLink.1
		$a_01_11 = {54 6c 64 63 74 6c 32 2e 53 65 61 72 63 68 43 6f 6e 74 72 6f 6c } //01 00  Tldctl2.SearchControl
		$a_01_12 = {54 6c 64 63 74 6c 32 2e 53 65 61 72 63 68 43 6f 6e 74 72 6f 6c 2e 31 } //00 00  Tldctl2.SearchControl.1
	condition:
		any of ($a_*)
 
}