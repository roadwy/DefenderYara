
rule Trojan_Win32_Flyagent_AN_MTB{
	meta:
		description = "Trojan:Win32/Flyagent.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 50 72 6f 78 79 43 72 65 64 65 6e 74 69 61 6c 73 } //2 SetProxyCredentials
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 5c 33 33 38 39 2e 62 61 74 } //2 Microsoft\3389.bat
		$a_01_2 = {6e 65 74 20 73 74 6f 70 20 74 65 72 6d 73 65 72 76 69 63 65 20 20 2f 79 } //2 net stop termservice  /y
		$a_01_3 = {74 61 6b 65 6f 77 6e 20 2f 46 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 74 65 72 6d 73 72 76 2e 64 6c 6c 20 2f 41 } //2 takeown /F c:\windows\system32\termsrv.dll /A
		$a_01_4 = {7b 4e 75 6d 4c 6f 63 6b 7d } //2 {NumLock}
		$a_01_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 63 6d 64 2e 65 78 65 } //2 taskkill /im cmd.exe
		$a_01_6 = {4d 54 49 30 4c 6a 49 79 4d 69 34 7a 4e 43 34 79 4e 44 5a 38 4f 44 49 34 4d 67 3d 3d } //2 MTI0LjIyMi4zNC4yNDZ8ODI4Mg==
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=14
 
}