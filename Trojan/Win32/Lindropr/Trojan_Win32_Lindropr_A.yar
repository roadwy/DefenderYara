
rule Trojan_Win32_Lindropr_A{
	meta:
		description = "Trojan:Win32/Lindropr.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 43 72 65 61 74 65 53 68 6f 72 74 63 75 74 28 57 53 63 72 69 70 74 2e 41 72 67 75 6d 65 6e 74 73 28 31 29 20 26 20 22 2e 6c 6e 6b 22 29 } //1 .CreateShortcut(WScript.Arguments(1) & ".lnk")
		$a_01_1 = {54 61 72 67 65 74 50 61 74 68 20 3d 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 } //1 TargetPath = "C:\Windows\System32\cmd.exe
		$a_01_2 = {41 72 67 75 6d 65 6e 74 73 20 3d 20 22 2f 63 20 5f 74 65 6d 70 2e 70 72 6a 78 20 22 20 26 20 63 68 72 28 33 34 29 20 26 20 57 53 63 72 69 70 74 2e 41 72 67 75 6d 65 6e 74 73 28 30 29 20 26 20 63 68 72 28 33 34 29 } //3 Arguments = "/c _temp.prjx " & chr(34) & WScript.Arguments(0) & chr(34)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}