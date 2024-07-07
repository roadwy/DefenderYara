
rule Backdoor_Win32_SpyAgent_A{
	meta:
		description = "Backdoor:Win32/SpyAgent.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 77 70 63 61 70 2e 64 6c 6c } //1 C:\wpcap.dll
		$a_01_1 = {6d 61 69 6c 2e 73 74 65 61 6c 74 68 2d 65 6d 61 69 6c 2e 63 6f 6d 3a 32 36 } //1 mail.stealth-email.com:26
		$a_01_2 = {25 73 5c 63 73 72 73 73 2e 65 78 65 } //1 %s\csrss.exe
		$a_01_3 = {43 6f 6d 70 75 74 65 72 20 49 50 20 41 64 64 72 65 73 73 3a 20 25 73 } //1 Computer IP Address: %s
		$a_01_4 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 74 65 78 74 2f 70 6c 61 69 6e 3b 20 63 68 61 72 73 65 74 3d 75 73 2d 61 73 63 69 69 } //1 Content-Type: text/plain; charset=us-ascii
		$a_01_5 = {53 50 59 41 47 45 4e 54 34 48 41 53 48 43 49 50 48 45 52 } //1 SPYAGENT4HASHCIPHER
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}