
rule Trojan_Win32_Katusha_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Katusha.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //01 00  powershell.exe
		$a_01_1 = {49 45 58 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 } //01 00  IEX(New-Object Net.WebClient)
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d } //01 00  DownloadString('https://cdn.discordapp.com
		$a_01_3 = {62 79 70 61 73 73 4d 6f 64 75 6c 65 4f 62 66 75 73 63 61 74 65 64 2e 62 69 6e } //00 00  bypassModuleObfuscated.bin
	condition:
		any of ($a_*)
 
}