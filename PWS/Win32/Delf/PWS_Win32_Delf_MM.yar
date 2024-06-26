
rule PWS_Win32_Delf_MM{
	meta:
		description = "PWS:Win32/Delf.MM,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 17 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 54 65 6e 63 65 6e 74 5c 49 65 } //01 00  Software\Tencent\Ie
		$a_01_1 = {62 6c 61 31 34 35 } //01 00  bla145
		$a_01_2 = {4c 69 73 74 42 6f 78 } //01 00  ListBox
		$a_01_3 = {62 67 35 64 78 38 65 } //01 00  bg5dx8e
		$a_01_4 = {46 69 72 73 74 } //01 00  First
		$a_01_5 = {44 58 6f 77 6e } //01 00  DXown
		$a_00_6 = {4e 61 6d 65 3d } //01 00  Name=
		$a_00_7 = {26 50 61 73 73 3d } //01 00  &Pass=
		$a_00_8 = {26 4d 61 63 3d } //01 00  &Mac=
		$a_01_9 = {44 6f 77 6e 2e 64 6c 6c } //01 00  Down.dll
		$a_01_10 = {48 6f 6f 6b 43 6c } //01 00  HookCl
		$a_01_11 = {48 6f 6f 6b 4f 6e } //01 00  HookOn
		$a_00_12 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 24 } //01 00  C:\Windows\iexplore.$
		$a_01_13 = {45 78 70 6c 4f 72 65 72 2e 65 78 65 } //01 00  ExplOrer.exe
		$a_00_14 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 41 } //01 00  GetComputerNameA
		$a_00_15 = {43 72 65 61 74 65 57 69 6e 64 6f 77 45 78 41 } //01 00  CreateWindowExA
		$a_00_16 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //01 00  UnhookWindowsHookEx
		$a_00_17 = {50 6f 73 74 4d 65 73 73 61 67 65 41 } //01 00  PostMessageA
		$a_01_18 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_00_19 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00  CallNextHookEx
		$a_01_20 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //01 00  HttpSendRequestA
		$a_00_21 = {48 74 74 70 51 75 65 72 79 49 6e 66 6f 41 } //01 00  HttpQueryInfoA
		$a_00_22 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41 } //00 00  HttpOpenRequestA
	condition:
		any of ($a_*)
 
}