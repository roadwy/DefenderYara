
rule Trojan_Win32_Qhost_GR{
	meta:
		description = "Trojan:Win32/Qhost.GR,SIGNATURE_TYPE_PEHSTR,15 00 15 00 08 00 00 04 00 "
		
	strings :
		$a_01_0 = {40 65 63 68 6f 20 6f 66 66 } //04 00  @echo off
		$a_01_1 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //04 00  \drivers\etc\hosts
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //04 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {70 69 6e 67 20 2d 6e 20 31 20 6c 6f 63 61 6c 68 6f 73 74 } //04 00  ping -n 1 localhost
		$a_01_4 = {66 6f 72 20 2f 6c 20 25 25 61 20 69 6e } //01 00  for /l %%a in
		$a_01_5 = {62 61 6e 63 6f 65 73 74 61 64 6f 2e 63 6c 20 3e 3e } //01 00  bancoestado.cl >>
		$a_01_6 = {73 61 6e 74 61 6e 64 65 72 2e 63 6c 20 3e 3e } //01 00  santander.cl >>
		$a_01_7 = {73 61 6e 74 61 6e 64 65 72 73 61 6e 74 69 61 67 6f 2e 63 6c 20 3e 3e } //00 00  santandersantiago.cl >>
	condition:
		any of ($a_*)
 
}