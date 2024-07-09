
rule TrojanProxy_Win32_Banker_BN{
	meta:
		description = "TrojanProxy:Win32/Banker.BN,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_02_1 = {41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 22 3d 22 68 74 74 70 3a 2f 2f [0-06] 2e [0-06] 2e [0-06] 2e [0-06] 2f 70 72 6f 78 79 70 61 63 } //1
		$a_00_2 = {64 65 6c 20 2f 71 20 2f 73 20 2f 66 20 22 25 44 61 74 61 44 69 72 25 22 } //1 del /q /s /f "%DataDir%"
		$a_00_3 = {72 65 67 65 64 69 74 20 2f 73 20 43 3a 5c 43 6f 6d 61 6e 64 6f 2e 52 65 67 } //1 regedit /s C:\Comando.Reg
		$a_02_4 = {73 74 61 72 74 20 2f 6d 69 6e 20 43 3a 5c [0-08] 2e 62 61 74 } //1
		$a_00_5 = {65 6e 76 69 61 64 65 64 65 6d 61 69 6c 2e 74 6d 70 } //1 enviadedemail.tmp
		$a_00_6 = {2f 69 6d 61 67 65 6e 73 2f 65 72 72 6f 2f 69 6e 64 65 78 2e 70 68 70 } //1 /imagens/erro/index.php
		$a_00_7 = {5c 00 50 00 72 00 6f 00 78 00 79 00 2e 00 65 00 78 00 65 00 } //1 \Proxy.exe
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}