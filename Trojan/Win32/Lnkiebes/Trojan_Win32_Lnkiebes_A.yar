
rule Trojan_Win32_Lnkiebes_A{
	meta:
		description = "Trojan:Win32/Lnkiebes.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 11 c7 45 ?? ?? ?? ?? ?? 68 a0 0f 00 00 e8 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 68 98 3a 00 00 e8 } //3
		$a_00_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 62 00 65 00 73 00 74 00 69 00 65 00 } //1 Internet Explorer.bestie
		$a_00_2 = {5c 00 24 00 4e 00 74 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 4b 00 42 00 39 00 37 00 31 00 30 00 30 00 30 00 24 00 5c 00 73 00 6b 00 79 00 2e 00 72 00 65 00 73 00 20 00 3d 00 3d 00 3d 00 } //1 \$NtUninstallKB971000$\sky.res ===
		$a_00_3 = {62 00 75 00 6c 00 6c 00 73 00 6b 00 79 00 2e 00 72 00 65 00 73 00 } //1 bullsky.res
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}