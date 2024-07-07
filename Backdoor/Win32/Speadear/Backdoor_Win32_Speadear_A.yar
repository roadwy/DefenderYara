
rule Backdoor_Win32_Speadear_A{
	meta:
		description = "Backdoor:Win32/Speadear.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b } //1 %SystemRoot%\System32\svchost.exe -k
		$a_01_1 = {73 70 64 69 72 73 2e 64 6c 6c } //1 spdirs.dll
		$a_01_2 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 28 53 76 63 68 6f 73 74 5c 6e 65 74 73 76 63 73 29 } //1 RegSetValueEx(Svchost\netsvcs)
		$a_01_3 = {49 6e 73 74 61 6c 6c 41 00 49 6e 73 74 61 6c 6c 42 00 49 6e 73 74 61 6c 6c 43 } //1 湉瑳污䅬䤀獮慴汬B湉瑳污䍬
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}