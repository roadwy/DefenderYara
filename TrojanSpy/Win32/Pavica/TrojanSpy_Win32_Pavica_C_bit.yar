
rule TrojanSpy_Win32_Pavica_C_bit{
	meta:
		description = "TrojanSpy:Win32/Pavica.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {56 55 6a 03 56 8b 35 ?? ?? ?? ?? 6a 03 53 6a ?? 68 ?? ?? ?? ?? ff d6 50 ff d7 } //1
		$a_01_1 = {2f 75 74 69 6c 73 2f 69 6e 65 74 5f 69 64 5f 6e 6f 74 69 66 79 2e 70 68 70 } //1 /utils/inet_id_notify.php
		$a_01_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 2c 00 53 00 68 00 65 00 6c 00 6c 00 45 00 78 00 65 00 63 00 5f 00 52 00 75 00 6e 00 44 00 4c 00 4c 00 } //1 rundll32.exe shell32.dll,ShellExec_RunDLL
		$a_03_3 = {68 75 10 ad 01 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 59 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}