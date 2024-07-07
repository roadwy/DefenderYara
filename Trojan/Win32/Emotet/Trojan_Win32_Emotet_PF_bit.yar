
rule Trojan_Win32_Emotet_PF_bit{
	meta:
		description = "Trojan:Win32/Emotet.PF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 18 8d b4 bd fc fb ff ff 88 5d ff 8b 1e 89 18 0f b6 5d ff 89 1e 8b 00 03 c3 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 84 85 fc fb ff ff 30 82 90 01 04 42 81 fa 4e 0e 00 00 72 90 00 } //1
		$a_01_1 = {73 63 20 64 65 6c 65 74 65 20 57 69 6e 44 65 66 65 6e 64 } //1 sc delete WinDefend
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 20 24 74 72 75 65 } //1 powershell Set-MpPreference -DisableRealtimeMonitoring $true
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}