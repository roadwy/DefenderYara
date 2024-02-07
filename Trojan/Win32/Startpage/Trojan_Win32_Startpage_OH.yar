
rule Trojan_Win32_Startpage_OH{
	meta:
		description = "Trojan:Win32/Startpage.OH,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 33 32 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 33 32 47 61 6d 65 73 5c 55 52 4c 2e 64 6c 6c 22 20 64 6f 73 65 74 } //04 00  rundll32 "C:\Program Files\Win32Games\URL.dll" doset
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 6f 31 2e 35 6b 35 2e 6e 65 74 2f 69 6e 74 65 72 66 61 63 65 3f 61 63 74 69 6f 6e 3d 69 6e 73 74 61 6c 6c 26 70 3d } //04 00  http://so1.5k5.net/interface?action=install&p=
		$a_01_2 = {72 65 67 73 76 72 33 32 20 73 79 73 70 6f 77 65 72 75 65 73 2e 64 6c 6c 20 2f 73 } //00 00  regsvr32 syspowerues.dll /s
	condition:
		any of ($a_*)
 
}