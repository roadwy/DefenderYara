
rule TrojanDownloader_O97M_Powdow_JA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.JA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 65 78 69 74 20 22 22 49 45 58 } //1 Shell("cmd.exe /c powershell.exe -noexit ""IEX
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 34 35 65 35 30 32 34 66 66 65 39 64 2e 73 6e 2e 6d 79 6e 65 74 6e 61 6d 65 2e 6e 65 74 2f 49 6e 76 6f 6b 65 2d 53 68 65 6c 6c 63 6f 64 65 2e 70 73 31 27 29 } //1 DownloadString('http://45e5024ffe9d.sn.mynetname.net/Invoke-Shellcode.ps1')
		$a_01_2 = {49 6e 76 6f 6b 65 2d 53 68 65 6c 6c 63 6f 64 65 20 2d 50 61 79 6c 6f 61 64 20 77 69 6e 64 6f 77 73 2f 6d 65 74 65 72 70 72 65 74 65 72 2f 72 65 76 65 72 73 65 5f 74 63 70 5f 72 63 34 } //1 Invoke-Shellcode -Payload windows/meterpreter/reverse_tcp_rc4
		$a_01_3 = {6c 68 6f 73 74 20 31 36 30 2e 31 35 35 2e 32 34 39 2e 38 36 20 2d 6c 70 6f 72 74 20 34 34 33 20 2d 52 43 34 50 41 53 53 57 4f 52 44 } //1 lhost 160.155.249.86 -lport 443 -RC4PASSWORD
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}