
rule Virus_Win16_Mailcab_C{
	meta:
		description = "Virus:Win16/Mailcab.C,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 4d 6f 64 75 6c 65 4e 61 6d 65 20 26 20 22 2e 62 61 73 22 } //1 = Environ("Temp") & "\" & ModuleName & ".bas"
		$a_00_1 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 24 28 22 63 6f 6d 73 70 65 63 22 29 20 26 20 22 20 2f 63 20 61 74 74 72 69 62 20 2d 53 20 2d 68 20 22 22 22 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 5c 4b 34 2e 58 4c 53 22 } //1 Shell Environ$("comspec") & " /c attrib -S -h """ & Application.StartupPath & "\K4.XLS"
		$a_00_2 = {3d 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 22 20 26 20 56 53 20 26 20 22 5c 45 78 63 65 6c 5c 53 65 63 75 72 69 74 79 5c 41 63 63 65 73 73 56 42 4f 4d } //1 = "HKEY_CURRENT_USER\Software\Microsoft\Office\" & VS & "\Excel\Security\AccessVBOM
		$a_00_3 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 45 6e 76 69 72 6f 6e 24 28 22 63 6f 6d 73 70 65 63 22 29 20 26 20 22 20 2f 63 20 52 44 20 2f 53 20 2f 51 20 45 3a 5c 4b 4b 22 2c 20 76 62 48 69 64 65 2c 20 46 61 6c 73 65 } //1 WshShell.Run Environ$("comspec") & " /c RD /S /Q E:\KK", vbHide, False
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}