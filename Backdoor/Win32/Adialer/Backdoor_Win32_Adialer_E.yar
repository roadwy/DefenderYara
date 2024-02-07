
rule Backdoor_Win32_Adialer_E{
	meta:
		description = "Backdoor:Win32/Adialer.E,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 76 74 53 68 75 74 64 6f 77 6e 00 45 76 74 53 74 61 72 74 75 70 00 69 6e 73 74 00 72 75 6e 00 74 65 73 } //01 00 
		$a_01_1 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 74 72 79 } //01 00  if exist "%s" goto Retry
		$a_01_2 = {63 6d 64 20 2f 63 20 73 74 61 72 74 20 2f 6d 69 6e } //01 00  cmd /c start /min
		$a_00_3 = {52 61 73 45 6e 75 6d 44 65 76 69 63 65 73 41 } //01 00  RasEnumDevicesA
		$a_00_4 = {64 65 6c 20 22 25 73 22 } //01 00  del "%s"
		$a_01_5 = {47 65 74 41 64 61 70 74 65 72 73 49 6e 66 6f } //01 00  GetAdaptersInfo
		$a_01_6 = {47 65 74 54 68 72 65 61 64 44 65 73 6b 74 6f 70 } //00 00  GetThreadDesktop
	condition:
		any of ($a_*)
 
}