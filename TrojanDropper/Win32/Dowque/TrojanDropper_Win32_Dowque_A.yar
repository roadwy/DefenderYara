
rule TrojanDropper_Win32_Dowque_A{
	meta:
		description = "TrojanDropper:Win32/Dowque.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 "
		
	strings :
		$a_02_0 = {68 ff 00 00 00 8d 85 00 ff ff ff 50 e8 90 01 03 ff 85 c0 75 07 c6 85 00 ff ff ff 43 90 00 } //2
		$a_02_1 = {8a 85 00 ff ff ff 50 e8 90 01 03 ff 83 f8 01 1b c0 40 84 c0 75 07 c6 85 00 ff ff ff 43 90 00 } //2
		$a_00_2 = {45 78 70 6c 6f 72 65 72 5c 50 4c 55 47 49 4e 53 5c } //1 Explorer\PLUGINS\
		$a_01_3 = {48 6f 6f 6b 4f 6e } //1 HookOn
		$a_00_4 = {69 66 20 65 78 69 73 74 20 22 } //2 if exist "
		$a_00_5 = {45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 Explorer\ShellExecuteHooks
		$a_00_6 = {53 79 73 74 65 6d 4b 62 } //1 SystemKb
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}