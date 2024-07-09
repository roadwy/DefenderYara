
rule Trojan_Win32_Adialer{
	meta:
		description = "Trojan:Win32/Adialer,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {6d 6f 64 65 6d } //1 modem
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //1 SOFTWARE\Microsoft\Internet Explorer\Main
		$a_00_2 = {4d 5a 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c } //1 MZKERNEL32.DLL
		$a_00_3 = {6d 62 70 2d 72 2d 61 67 65 6e 74 } //1 mbp-r-agent
		$a_00_4 = {52 61 73 44 69 61 6c 41 } //1 RasDialA
		$a_00_5 = {43 72 65 61 74 65 4d 75 74 65 78 } //1 CreateMutex
		$a_02_6 = {55 8b ec b8 ?? ?? ?? 00 e8 ?? ?? ?? ?? 53 56 ?? ?? ?? 89 ?? ?? e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 45 08 68 ?? ?? ?? 00 ?? ?? a3 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 3d ?? ?? 00 00 ?? 0f 84 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 68 ?? ?? ?? 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1) >=7
 
}
rule Trojan_Win32_Adialer_2{
	meta:
		description = "Trojan:Win32/Adialer,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 81 c4 5c ff ff ff ff 35 ad 47 40 00 e8 7a 07 00 00 68 a0 00 00 00 8d 85 5c ff ff ff 50 e8 fd 06 00 00 c7 85 5c ff ff ff a0 00 00 00 8d 85 5c ff ff ff 50 ff 35 ad 47 40 00 e8 3b 07 00 00 83 f8 06 74 1e 68 e8 03 00 00 e8 de 06 00 00 8d 85 5c ff ff ff 50 ff 35 ad 47 40 00 e8 1a 07 00 00 eb dd 68 90 01 00 00 e8 c0 06 00 00 c9 c3 } //10
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_01_2 = {52 61 73 44 69 61 6c 41 } //1 RasDialA
		$a_01_3 = {73 74 72 73 74 72 } //1 strstr
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}