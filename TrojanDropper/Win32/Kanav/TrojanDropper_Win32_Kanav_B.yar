
rule TrojanDropper_Win32_Kanav_B{
	meta:
		description = "TrojanDropper:Win32/Kanav.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 63 61 6c 63 31 2e 65 78 65 } //1 c:\windows\calc1.exe
		$a_01_1 = {25 73 5c 41 59 4c 61 75 6e 63 68 2e 65 78 65 } //1 %s\AYLaunch.exe
		$a_01_2 = {25 73 5c 75 73 70 31 30 2e 64 6c 6c 2e 62 61 6b } //1 %s\usp10.dll.bak
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}