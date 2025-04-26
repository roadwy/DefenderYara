
rule Trojan_WinNT_Sirefef_N{
	meta:
		description = "Trojan:WinNT/Sirefef.N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 24 00 4e 00 74 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 4b 00 42 00 25 00 75 00 24 00 } //1 \systemroot\$NtUninstallKB%u$
		$a_00_1 = {65 61 6f 69 6d 6e 71 61 7a 77 } //1 eaoimnqazw
		$a_03_2 = {8b 7d 08 8b f0 83 e6 1f 66 0f be b6 ?? ?? ?? ?? 0f ac d0 05 66 89 34 4f c1 ea 05 8b f1 49 85 f6 75 de } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_WinNT_Sirefef_N_2{
	meta:
		description = "Trojan:WinNT/Sirefef.N,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 24 00 4e 00 74 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 4b 00 42 00 25 00 75 00 24 00 } //1 \systemroot\$NtUninstallKB%u$
		$a_00_1 = {65 61 6f 69 6d 6e 71 61 7a 77 } //1 eaoimnqazw
		$a_03_2 = {8b 7d 08 8b f0 83 e6 1f 66 0f be b6 ?? ?? ?? ?? 0f ac d0 05 66 89 34 4f c1 ea 05 8b f1 49 85 f6 75 de } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}