
rule Trojan_Win32_Adialer{
	meta:
		description = "Trojan:Win32/Adialer,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 6f 64 65 6d } //01 00  modem
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //01 00  SOFTWARE\Microsoft\Internet Explorer\Main
		$a_00_2 = {4d 5a 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c } //01 00  MZKERNEL32.DLL
		$a_00_3 = {6d 62 70 2d 72 2d 61 67 65 6e 74 } //01 00  mbp-r-agent
		$a_00_4 = {52 61 73 44 69 61 6c 41 } //01 00  RasDialA
		$a_00_5 = {43 72 65 61 74 65 4d 75 74 65 78 } //01 00  CreateMutex
		$a_02_6 = {55 8b ec b8 90 01 03 00 e8 90 01 04 53 56 90 01 03 89 90 01 02 e8 90 01 04 84 c0 0f 84 90 01 04 ff 15 90 01 04 8b 45 08 68 90 01 03 00 90 01 02 a3 90 01 03 00 ff 15 90 01 03 00 ff 15 90 01 03 00 3d 90 01 02 00 00 90 01 01 0f 84 90 01 04 e8 90 01 04 50 e8 90 01 04 8d 85 90 01 04 68 90 01 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Adialer_2{
	meta:
		description = "Trojan:Win32/Adialer,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {55 8b ec 81 c4 5c ff ff ff ff 35 ad 47 40 00 e8 7a 07 00 00 68 a0 00 00 00 8d 85 5c ff ff ff 50 e8 fd 06 00 00 c7 85 5c ff ff ff a0 00 00 00 8d 85 5c ff ff ff 50 ff 35 ad 47 40 00 e8 3b 07 00 00 83 f8 06 74 1e 68 e8 03 00 00 e8 de 06 00 00 8d 85 5c ff ff ff 50 ff 35 ad 47 40 00 e8 1a 07 00 00 eb dd 68 90 01 00 00 e8 c0 06 00 00 c9 c3 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00  ShellExecuteA
		$a_01_2 = {52 61 73 44 69 61 6c 41 } //01 00  RasDialA
		$a_01_3 = {73 74 72 73 74 72 } //00 00  strstr
	condition:
		any of ($a_*)
 
}