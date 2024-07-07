
rule Trojan_Win32_Farfli_GW_MTB{
	meta:
		description = "Trojan:Win32/Farfli.GW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 0c 24 3b c8 49 81 c4 04 00 00 00 33 cd 41 f7 c1 6d 4d 43 46 e9 a8 9f 01 00 } //10
		$a_01_1 = {54 65 6c 65 67 72 61 6d 44 6c 6c 2e 64 6c 6c } //1 TelegramDll.dll
		$a_01_2 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 } //1 CreateProcess
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_4 = {63 59 72 65 65 6e 51 69 6c 6c 6d } //1 cYreenQillm
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}