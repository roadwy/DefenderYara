
rule TrojanDownloader_Win16_Pshdlexec{
	meta:
		description = "TrojanDownloader:Win16/Pshdlexec,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {3a 38 30 2f 67 6b 6e 2e 68 74 6d 6c 3f } //2 :80/gkn.html?
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 2d 6e 6f 65 78 69 74 20 2d 63 20 49 45 58 20 28 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 } //1 powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -noprofile -noexit -c IEX ((New-Object Net.WebClient).DownloadString('
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 50 20 2d 4e 6f 6e 49 20 2d 57 20 48 69 64 64 65 6e 20 2d 45 78 65 63 20 42 79 70 61 73 73 20 49 45 58 20 28 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 } //1 powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX ((New-Object Net.WebClient).DownloadString('
		$a_01_3 = {49 6e 76 6f 6b 65 2d 53 68 65 6c 6c 63 6f 64 65 20 2d 50 61 79 6c 6f 61 64 20 77 69 6e 64 6f 77 73 2f 6d 65 74 65 72 70 72 65 74 65 72 2f } //4 Invoke-Shellcode -Payload windows/meterpreter/
		$a_01_4 = {2d 4c 68 6f 73 74 20 35 32 2e 34 31 2e 31 32 32 2e 33 38 20 2d 4c 70 6f 72 74 20 34 34 33 20 2d 46 6f 72 63 65 } //2 -Lhost 52.41.122.38 -Lport 443 -Force
		$a_01_5 = {53 65 74 41 74 74 72 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 63 6f 6e 66 69 67 2e 76 62 73 22 2c 20 76 62 48 69 64 64 65 6e } //2 SetAttr "C:\Users\Public\config.vbs", vbHidden
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*4+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=7
 
}