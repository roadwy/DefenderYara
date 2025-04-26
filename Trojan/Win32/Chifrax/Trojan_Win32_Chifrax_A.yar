
rule Trojan_Win32_Chifrax_A{
	meta:
		description = "Trojan:Win32/Chifrax.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_02_0 = {6a 00 52 68 94 01 00 00 56 53 ff 15 ?? ?? ?? 00 33 c0 8a 0c 30 32 c8 88 0c 30 40 3d 94 01 00 00 72 f0 b9 65 00 00 00 } //10
		$a_00_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 } //2 SYSTEM\CurrentControlSet\Services\%s
		$a_00_2 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 54 73 76 63 73 } //2 %SystemRoot%\System32\svchost.exe -k neTsvcs
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 52 4f 53 4f 46 54 5c 57 69 6e 64 6f 57 53 20 6e 74 5c 43 75 72 52 45 4e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 4f 53 54 } //2 SOFTWARE\MicROSOFT\WindoWS nt\CurRENtVersion\SvcHOST
		$a_01_4 = {52 65 4d 61 72 6b } //1 ReMark
		$a_01_5 = {49 6e 54 69 6d 65 } //1 InTime
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}