
rule Trojan_Win32_LokiBot_CN_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 e7 d1 ea 83 e2 fc 8d 04 52 89 ca 29 c2 0f b6 ?? ?? ?? ?? ?? 30 14 0e f7 d8 0f b6 ?? ?? ?? ?? ?? ?? 30 44 0e 01 83 c1 ?? 39 cb 75 } //5
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 73 74 61 6c 6c 65 72 5c 52 75 6e 4f 6e 63 65 45 6e 74 72 69 65 73 } //1 Software\Microsoft\Windows\CurrentVersion\Installer\RunOnceEntries
		$a_81_2 = {5c 6d 73 69 65 78 65 63 20 2f 56 } //1 \msiexec /V
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=7
 
}