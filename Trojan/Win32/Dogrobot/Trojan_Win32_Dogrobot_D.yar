
rule Trojan_Win32_Dogrobot_D{
	meta:
		description = "Trojan:Win32/Dogrobot.D,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6d 64 20 2f 63 20 63 61 63 6c 73 20 22 25 73 22 20 2f 65 20 2f 70 20 65 76 65 72 79 6f 6e 65 3a 66 } //01 00  cmd /c cacls "%s" /e /p everyone:f
		$a_00_1 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 } //01 00  if exist "%s" goto 
		$a_01_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00  KeServiceDescriptorTable
		$a_00_3 = {33 36 30 74 72 61 79 2e 65 78 65 } //01 00  360tray.exe
		$a_00_4 = {5c 75 70 64 61 74 65 2e 64 6c 6c } //01 00  \update.dll
		$a_00_5 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 20 64 72 6f 70 } //00 00  rundll32.exe %s, drop
	condition:
		any of ($a_*)
 
}