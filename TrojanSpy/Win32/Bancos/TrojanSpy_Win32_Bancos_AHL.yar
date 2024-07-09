
rule TrojanSpy_Win32_Bancos_AHL{
	meta:
		description = "TrojanSpy:Win32/Bancos.AHL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {2f 76 20 41 6e 74 69 56 69 72 75 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 78 30 30 30 30 30 30 30 31 20 2f 66 } ///v AntiVirusDisableNotify /t REG_DWORD /d 0x00000001 /f  1
		$a_00_1 = {74 6d 72 5f 69 6e 6a 65 63 74 54 69 6d 65 72 } //1 tmr_injectTimer
		$a_03_2 = {d3 e8 89 45 ?? 8b 4d ?? bb 01 00 00 00 d3 e3 8b 45 ?? 99 f7 fb 89 55 ?? b9 00 01 00 00 8b 45 ?? 99 f7 f9 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}