
rule Trojan_Win32_FlyStudio_CH_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 6a 65 63 74 2e 65 78 65 } //01 00  inject.exe
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 67 69 74 65 65 2e 63 6f 6d 2f 6a 73 6d 68 2f 68 77 69 64 2f 72 61 77 2f 6d 61 73 74 65 72 2f 68 77 69 64 2e 74 78 74 } //01 00  https://gitee.com/jsmh/hwid/raw/master/hwid.txt
		$a_01_2 = {6a 73 6d 68 20 54 6f 6f 6c 43 68 65 73 74 5c 41 6e 74 69 42 61 6e 2e 64 6c 6c } //01 00  jsmh ToolChest\AntiBan.dll
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 77 77 72 2e 6c 61 6e 7a 6f 75 69 2e 63 6f 6d } //01 00  https://wwr.lanzoui.com
		$a_01_4 = {68 74 74 70 73 3a 2f 2f 72 65 73 2e 61 62 65 69 6d 2e 63 6e 2f 61 70 69 2d 6c 61 6e 7a 6f 75 5f 6a 78 3f 75 72 6c 3d 68 74 74 70 73 3a 2f 2f 77 77 72 2e 6c 61 6e 7a 6f 75 69 2e 63 6f 6d 2f 69 75 75 49 71 73 63 6e 30 72 61 } //01 00  https://res.abeim.cn/api-lanzou_jx?url=https://wwr.lanzoui.com/iuuIqscn0ra
		$a_01_5 = {56 4d 50 72 6f 74 65 63 74 20 62 65 67 69 6e } //01 00  VMProtect begin
		$a_01_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_7 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //01 00  QueryPerformanceCounter
		$a_01_8 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00  GetTickCount
	condition:
		any of ($a_*)
 
}