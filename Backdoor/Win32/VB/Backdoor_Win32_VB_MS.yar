
rule Backdoor_Win32_VB_MS{
	meta:
		description = "Backdoor:Win32/VB.MS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 63 6b 53 65 72 76 65 72 5f 43 6f 6e 6e 65 63 74 } //1 sckServer_Connect
		$a_00_1 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 Select * from AntiVirusProduct
		$a_01_2 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 62 64 65 6c 68 61 6d 69 64 5c 4d 79 20 44 6f 63 75 6d 65 6e 74 73 5c 50 72 6f 67 72 61 6d 6d 65 72 65 6e 5c 41 72 61 62 61 69 6e 2d 41 74 74 61 63 6b 65 72 5c 41 64 6d 69 6e 5c 4d 53 4e 4d 65 73 73 65 6e 67 65 72 41 50 49 2e 74 6c 62 } //1 C:\Documents and Settings\Abdelhamid\My Documents\Programmeren\Arabain-Attacker\Admin\MSNMessengerAPI.tlb
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}