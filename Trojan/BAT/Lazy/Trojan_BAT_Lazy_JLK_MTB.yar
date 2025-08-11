
rule Trojan_BAT_Lazy_JLK_MTB{
	meta:
		description = "Trojan:BAT/Lazy.JLK!MTB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 41 6e 61 6c 79 73 69 73 } //2 AntiAnalysis
		$a_01_1 = {41 64 64 54 6f 57 69 6e 64 6f 77 73 44 65 66 65 6e 64 65 72 45 78 63 6c 75 73 69 6f 6e 73 } //2 AddToWindowsDefenderExclusions
		$a_01_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //2 CheckRemoteDebuggerPresent
		$a_01_3 = {52 4d 4c 6f 61 64 65 72 2e 4c 6f 67 69 6e 43 6c 61 73 73 57 69 6e 64 6f 77 73 2e 72 65 73 6f 75 72 63 65 73 } //2 RMLoader.LoginClassWindows.resources
		$a_01_4 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 6e 00 33 00 4b 00 64 00 4d 00 36 00 4d 00 4c 00 } //2 https://pastebin.com/raw/n3KdM6ML
		$a_01_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 39 00 33 00 2e 00 31 00 32 00 33 00 2e 00 38 00 34 00 2e 00 30 00 2f 00 43 00 65 00 6c 00 42 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00 } //2 http://93.123.84.0/CelBuild.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}