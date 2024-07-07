
rule Trojan_Win32_Qbot_AV_MSR{
	meta:
		description = "Trojan:Win32/Qbot.AV!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 55 08 8b 90 01 01 8b 90 01 01 fc 8d 94 01 c2 5a 00 00 8b 45 08 89 10 90 00 } //1
		$a_01_1 = {70 00 64 00 66 00 32 00 64 00 6a 00 76 00 75 00 20 00 30 00 2e 00 37 00 2e 00 31 00 34 00 20 00 28 00 44 00 6a 00 56 00 75 00 4c 00 69 00 62 00 72 00 65 00 20 00 33 00 2e 00 35 00 2e 00 32 00 35 00 2c 00 20 00 70 00 6f 00 70 00 70 00 6c 00 65 00 72 00 20 00 30 00 2e 00 31 00 38 00 2e 00 34 00 2c 00 20 00 47 00 4e 00 4f 00 4d 00 45 00 20 00 58 00 53 00 4c 00 54 00 20 00 31 00 2e 00 31 00 2e 00 32 00 36 00 2c 00 20 00 47 00 4e 00 4f 00 4d 00 45 00 20 00 58 00 4d 00 4c 00 20 00 32 00 2e 00 37 00 2e 00 38 00 29 00 } //1 pdf2djvu 0.7.14 (DjVuLibre 3.5.25, poppler 0.18.4, GNOME XSLT 1.1.26, GNOME XML 2.7.8)
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qbot_AV_MSR_2{
	meta:
		description = "Trojan:Win32/Qbot.AV!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 8b 11 2b d6 8b 45 08 89 10 5e 8b e5 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}