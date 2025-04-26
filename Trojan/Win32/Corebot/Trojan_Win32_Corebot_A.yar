
rule Trojan_Win32_Corebot_A{
	meta:
		description = "Trojan:Win32/Corebot.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 63 61 6c 5c 48 65 61 72 74 62 65 61 74 31 33 } //1 Local\Heartbeat13
		$a_01_1 = {63 6d 64 2e 73 6b 69 70 5f 75 6e 6c 6f 61 64 } //1 cmd.skip_unload
		$a_01_2 = {63 6f 72 65 2e 64 67 61 2e 6b 65 79 5f 66 69 6e 67 65 72 70 72 69 6e 74 } //1 core.dga.key_fingerprint
		$a_01_3 = {63 6f 72 65 2e 64 67 61 2e 7a 6f 6e 65 73 } //1 core.dga.zones
		$a_01_4 = {63 6f 72 65 2e 64 67 61 2e 67 72 6f 75 70 } //1 core.dga.group
		$a_01_5 = {63 6f 72 65 2e 64 67 61 2e 64 6f 6d 61 69 6e 73 5f 63 6f 75 6e 74 } //1 core.dga.domains_count
		$a_01_6 = {63 6f 72 65 2e 64 67 61 2e 75 72 6c 5f 70 61 74 68 } //1 core.dga.url_path
		$a_01_7 = {63 6f 72 65 2e 73 65 72 76 65 72 5f 6b 65 79 } //1 core.server_key
		$a_01_8 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 4e 6f 4c 6f 67 6f 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 55 6e 72 65 73 74 72 69 63 74 65 64 20 2d 46 69 6c 65 20 22 25 73 22 20 3e 20 22 25 73 22 } //1 powershell.exe -NonInteractive -NoProfile -NoLogo -ExecutionPolicy Unrestricted -File "%s" > "%s"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}