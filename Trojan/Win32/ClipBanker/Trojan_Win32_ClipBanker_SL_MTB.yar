
rule Trojan_Win32_ClipBanker_SL_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //2 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {53 76 63 48 6f 73 74 55 70 64 61 74 65 } //2 SvcHostUpdate
		$a_01_2 = {53 76 63 48 6f 73 74 53 79 73 } //2 SvcHostSys
		$a_01_3 = {73 74 61 72 74 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 52 75 6e 74 69 6d 65 20 42 72 6f 6b 65 72 2e 65 78 65 } //2 start C:\Windows\Runtime Broker.exe
		$a_01_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 } //2 C:\Windows\System32\svchost
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}