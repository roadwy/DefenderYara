
rule Trojan_Win64_Mikey_SXG_MTB{
	meta:
		description = "Trojan:Win64/Mikey.SXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_03_0 = {49 83 c7 01 48 63 c8 48 89 c8 48 f7 e3 48 c1 ea 05 48 8d 04 d2 48 c1 e0 02 48 29 c1 0f b6 44 0c ?? 41 88 47 ff 49 39 f7 75 } //10
		$a_01_1 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 52 55 4e 20 2f 54 4e 20 22 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 44 69 73 6b 43 6c 65 61 6e 75 70 5c 53 69 6c 65 6e 74 43 6c 65 61 6e 75 70 22 20 2f 49 } //2 schtasks.exe /RUN /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" /I
		$a_01_2 = {5b 2d 5d 20 53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 } //1 [-] ShellExecuteEx
		$a_01_3 = {5b 2b 5d 20 52 75 6e 6e 69 6e 67 20 65 6d 62 65 64 64 65 64 20 31 2e 65 78 65 } //1 [+] Running embedded 1.exe
		$a_01_4 = {5b 2b 5d 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 70 72 69 76 69 6c 65 67 65 20 64 65 74 65 63 74 65 64 } //1 [+] Administrator privilege detected
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=15
 
}