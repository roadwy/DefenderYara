
rule Trojan_Win32_Niktol_RPY_MTB{
	meta:
		description = "Trojan:Win32/Niktol.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 74 20 68 69 64 5f 65 78 65 63 } //01 00  set hid_exec
		$a_01_1 = {25 68 69 64 5f 65 78 65 63 75 74 61 62 6c 65 25 } //01 00  %hid_executable%
		$a_01_2 = {64 65 6c 20 2f 71 20 2f 66 20 25 68 69 64 5f 65 78 65 63 75 74 61 62 6c 65 25 20 3e 6e 75 6c 20 32 3e 26 31 } //01 00  del /q /f %hid_executable% >nul 2>&1
		$a_01_3 = {69 66 20 65 78 69 73 74 20 22 25 74 6d 70 25 5c 7a 7a 7a 22 20 28 73 65 74 20 63 68 65 63 6b 3d 65 78 65 63 75 74 65 64 29 20 65 6c 73 65 20 28 73 65 74 20 63 68 65 63 6b 3d 6e 6f 74 5f 65 78 65 63 75 74 65 64 29 } //01 00  if exist "%tmp%\zzz" (set check=executed) else (set check=not_executed)
		$a_01_4 = {48 69 64 65 45 78 74 72 61 63 74 41 6e 69 6d 61 74 69 6f 6e 3d 31 } //00 00  HideExtractAnimation=1
	condition:
		any of ($a_*)
 
}