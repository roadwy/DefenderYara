
rule Trojan_Win32_Emotet_DR{
	meta:
		description = "Trojan:Win32/Emotet.DR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 00 73 00 68 00 6f 00 72 00 74 00 63 00 75 00 74 00 73 00 28 00 65 00 2e 00 67 00 2e 00 77 00 65 00 62 00 6f 00 74 00 68 00 65 00 72 00 66 00 69 00 72 00 73 00 74 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 49 00 55 00 6e 00 69 00 76 00 65 00 72 00 73 00 69 00 74 00 79 00 62 00 79 00 } //1 Mshortcuts(e.g.webotherfirstinstallationIUniversityby
		$a_01_1 = {47 00 4d 00 45 00 20 00 6c 00 20 00 50 00 56 00 66 00 66 00 20 00 73 00 77 00 20 00 4c 00 51 00 70 00 79 00 20 00 4d 00 77 00 58 00 56 00 49 00 6f 00 } //1 GME l PVff sw LQpy MwXVIo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}