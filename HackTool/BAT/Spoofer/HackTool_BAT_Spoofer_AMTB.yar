
rule HackTool_BAT_Spoofer_AMTB{
	meta:
		description = "HackTool:BAT/Spoofer!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 09 00 00 "
		
	strings :
		$a_80_0 = {44 49 53 4b 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 73 70 6f 6f 66 65 64 2e } //DISK successfully spoofed.  2
		$a_80_1 = {4d 41 43 20 61 64 64 72 65 73 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 73 70 6f 6f 66 65 64 2e } //MAC address successfully spoofed.  2
		$a_80_2 = {50 72 6f 64 75 63 74 20 49 44 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 73 70 6f 6f 66 65 64 2e } //Product ID successfully spoofed.  2
		$a_80_3 = {4d 61 63 68 69 6e 65 20 47 55 49 44 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 73 70 6f 6f 66 65 64 2e } //Machine GUID successfully spoofed.  2
		$a_80_4 = {48 77 50 72 6f 66 69 6c 65 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 73 70 6f 6f 66 65 64 2e } //HwProfile successfully spoofed.  2
		$a_80_5 = {53 65 63 48 65 78 2d 47 55 49 } //SecHex-GUI  1
		$a_80_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_8 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*1+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100+(#a_80_8  & 1)*-100) >=11
 
}