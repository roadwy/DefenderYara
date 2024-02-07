
rule HackTool_Win32_AutoKMS_C{
	meta:
		description = "HackTool:Win32/AutoKMS.C,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 65 74 75 70 3d 4b 4d 53 70 69 63 6f 2d 73 65 74 75 70 2e 65 78 65 } //01 00  Setup=KMSpico-setup.exe
		$a_00_1 = {53 65 74 75 70 3d 6b 6d 73 68 2e 65 78 65 } //01 00  Setup=kmsh.exe
		$a_00_2 = {53 65 74 75 70 3d 64 6c 6c 73 65 72 76 73 79 73 2e 65 78 65 } //01 00  Setup=dllservsys.exe
		$a_00_3 = {53 65 74 75 70 3d 6b 6d 73 62 2e 65 78 65 } //01 00  Setup=kmsb.exe
		$a_00_4 = {53 65 74 75 70 3d 6b 6d 73 70 69 63 6f 68 2e 65 78 65 } //01 00  Setup=kmspicoh.exe
		$a_00_5 = {53 65 74 75 70 3d 6b 6d 73 64 6c 6c 69 2e 65 78 65 } //01 00  Setup=kmsdlli.exe
		$a_00_6 = {53 65 74 75 70 3d 6b 6d 73 70 69 63 6f 76 2e 65 78 65 } //0a 00  Setup=kmspicov.exe
		$a_02_7 = {46 75 6c 6c 43 72 61 63 6b 2e 76 6e 5f 4b 4d 53 70 69 63 6f 5f 31 30 2e 90 01 03 5f 73 65 74 75 70 2e 72 61 72 90 00 } //01 00 
		$a_00_8 = {50 61 73 73 77 6f 72 64 20 3a 20 66 75 6c 6c 63 72 61 63 6b 2e 76 6e } //0a 00  Password : fullcrack.vn
		$a_02_9 = {40 24 26 25 90 01 02 5c 4b 4d 53 70 69 63 6f 2d 73 65 74 75 70 2e 65 78 65 90 00 } //01 00 
		$a_02_10 = {40 24 26 25 90 01 02 5c 6b 6d 73 64 6c 6c 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}