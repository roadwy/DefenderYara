
rule TrojanSpy_Win32_Delf_gen_D{
	meta:
		description = "TrojanSpy:Win32/Delf.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,2c 01 18 01 11 00 00 64 00 "
		
	strings :
		$a_00_0 = {48 4f 4f 4b 5f 44 4c 4c 2e 64 6c 6c } //64 00  HOOK_DLL.dll
		$a_01_1 = {48 6f 6f 6b 4f 6e } //0a 00  HookOn
		$a_00_2 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //0a 00  Content-Type: application/x-www-form-urlencoded
		$a_00_3 = {43 3a 5c 52 46 5f 46 49 4c 45 5c } //0a 00  C:\RF_FILE\
		$a_00_4 = {52 46 6c 6f 67 69 6e 2e 65 78 65 } //0a 00  RFlogin.exe
		$a_00_5 = {52 46 2e 65 78 65 } //0a 00  RF.exe
		$a_00_6 = {52 46 5f 4f 6e 6c 69 6e 65 2e 62 69 6e } //0a 00  RF_Online.bin
		$a_00_7 = {54 6f 4d 61 69 6c 3d } //0a 00  ToMail=
		$a_00_8 = {26 55 73 65 72 3d } //0a 00  &User=
		$a_00_9 = {26 50 61 73 73 3d } //0a 00  &Pass=
		$a_00_10 = {26 53 65 72 76 65 72 3d } //0a 00  &Server=
		$a_00_11 = {26 57 69 6e 42 61 6e 42 65 6e 3d } //0a 00  &WinBanBen=
		$a_00_12 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //0a 00  CallNextHookEx
		$a_01_13 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //0a 00  ReadProcessMemory
		$a_01_14 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //0a 00  InternetReadFile
		$a_01_15 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //0a 00  InternetOpenA
		$a_00_16 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //00 00  InternetConnectA
	condition:
		any of ($a_*)
 
}